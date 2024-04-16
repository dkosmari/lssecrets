/*
 * lssecrets - A tool to list data from the keyring.
 * Copyright 2024  Daniel K. O. (dkosmari)
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <libsecret-1/libsecret/secret.h>

#include <giomm/application.h>
#include <giomm/init.h>
#include <glibmm/datetime.h>
#include <glibmm/error.h>
#include <glibmm/main.h>


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


using std::cout;
using std::clog;
using std::cerr;
using std::endl;

using namespace std::literals;


#if HAVE_GLIBMM_2_68
#define AF_NON_UNIQUE Gio::Application::Flags::NON_UNIQUE
#define OEF_IN_MAIN   Glib::OptionEntry::Flags::IN_MAIN
#else
#define AF_NON_UNIQUE Gio::ApplicationFlags::APPLICATION_NON_UNIQUE
#define OEF_IN_MAIN   Glib::OptionEntry::Flags::FLAG_IN_MAIN
#endif


template<typename T>
class GObjectWrapper {
    T* ptr = nullptr;

public:

    GObjectWrapper() noexcept = default;


    explicit
    GObjectWrapper(T* p, bool add_ref = false)
        noexcept :
        ptr{p}
    {
        if (add_ref)
            ref();
    }


    GObjectWrapper(const GObjectWrapper& other)
        noexcept :
        ptr{other.ptr}
    {
        ref();
    }


    GObjectWrapper(GObjectWrapper&& other)
        noexcept :
        ptr{other.ptr}
    {
        other.ptr = nullptr;
    }


    GObjectWrapper&
    operator =(const GObjectWrapper& other)
        noexcept
    {
        unref();
        ptr = other.ptr;
        ref();
        return *this;
    }


    GObjectWrapper&
    operator =(GObjectWrapper&& other)
        noexcept
    {
        unref();
        ptr = other.ptr;
        other.ptr = nullptr;
        return *this;
    }


    ~GObjectWrapper()
    {
        unref();
    }


    void
    ref()
    {
        if (ptr)
            g_object_ref(ptr);
    }


    void
    unref()
    {
        if (ptr)
            g_object_unref(ptr);
    }


    T*
    get()
        noexcept
    {
        return ptr;
    }


    operator T* ()
        noexcept
    {
        return get();
    }


    operator GDBusProxy* ()
        noexcept
    {
        return G_DBUS_PROXY(get());
    }


};


template<typename T>
GObjectWrapper<T>
take(T* obj)
{
    return GObjectWrapper<T>{obj, false};
}


template<typename T>
GObjectWrapper<T>
borrow(T* obj)
{
    return GObjectWrapper<T>{obj, true};
}


template<typename T>
std::vector<GObjectWrapper<T>>
to_vector(GList* list)
{
    std::vector<GObjectWrapper<T>> result;

    try {
        for (GList* n = list; n; n = n->next) {
            T* ptr = reinterpret_cast<T*>(n->data);
            n->data = nullptr;
            result.push_back(take(ptr));
        }
        g_list_free(list);
    }
    catch (...) {
        g_list_free_full(list, g_object_unref);
        throw;
    }

    return result;
}


std::optional<std::string>
to_string(gchar* s)
{
    if (!s)
        return {};

    std::string result = s;
    g_free(s);
    return result;
}


std::optional<std::string>
to_string(const gchar* s)
{
    if (!s)
        return {};

    std::string result = s;
    return result;
}


std::string
to_string(const gchar* ptr, gsize len)
{
    std::ostringstream out;
    out << std::setbase(16)
        << std::setfill('0');

    for (gsize i = 0; i < len; ++i)
        out << std::setw(2)
            << static_cast<unsigned char>(ptr[i]);

    return out.str();
}


std::optional<std::string>
timestamp_to_string(guint64 t)
{
    auto dt = Glib::DateTime::create_now_local(t);
    return dt.format("%F %T").raw();
}


std::map<std::string, std::string>
to_map(GHashTable* table)
{
    try {
        std::map<std::string, std::string> result;

        GHashTableIter iter;
        gpointer key, val;
        g_hash_table_iter_init(&iter, table);
        while (g_hash_table_iter_next(&iter, &key, &val)) {
            std::string key_s = reinterpret_cast<const char*>(key);
            std::string val_s = reinterpret_cast<const char*>(val);
            result[key_s] = val_s;
        }
        g_hash_table_unref(table);

        return result;
    }
    catch (...) {
        g_hash_table_unref(table);
        throw;
    }
}



std::runtime_error
to_error(GError* raw_err)
{
    Glib::Error err{raw_err}; // will free raw_err on destructor

    std::string msg;

    if (err.domain() != SECRET_ERROR) {
        msg = "Couldn't get secret service.";
    } else {
        switch (err.code()) {
        case SECRET_ERROR_PROTOCOL:
            msg = "Received invalid data from secret service.";
            break;
        case SECRET_ERROR_IS_LOCKED:
            msg = "Secret item or collection is locked.";
            break;
        case SECRET_ERROR_NO_SUCH_OBJECT:
            msg = "Secret item or collection not found.";
            break;
        case SECRET_ERROR_ALREADY_EXISTS:
            msg = "Secret item or collection already exists.";
            break;
        }
    }

    msg += " "s + err.what();

    return std::runtime_error{msg};
}


[[noreturn]]
void
throw_error(GError* raw_err)
{
    throw to_error(raw_err);
}


struct App : Gio::Application {


    enum Detail : int {
        Service     = 0,
        Collections = 1,
        Items       = 2,
        Attributes  = 3,
        Secrets     = 4
    };


    int detail = Detail::Items;
    bool unlock_flag = false;
    bool version_flag = false;

    Glib::OptionGroup main_group{"", ""};
    Glib::OptionEntry detail_opt;
    Glib::OptionEntry unlock_opt;
    Glib::OptionEntry version_opt;

    std::optional<GObjectWrapper<SecretService>> service;


    App() :
        Gio::Application{"lssecrets.dkosmari.github.com", AF_NON_UNIQUE}
    {
        set_option_context_summary("Show keyring secrets using libsecret.");
        set_option_context_description(PACKAGE_NAME " <" PACKAGE_URL ">\n"
                                       "Bug reports <" PACKAGE_BUGREPORT ">\n");

        detail_opt.set_flags(OEF_IN_MAIN);
        detail_opt.set_long_name("detail");
        detail_opt.set_short_name('d');
        detail_opt.set_description("Set detail of detail, where N is:\n"
                                    "                                  0 = service\n"
                                    "                                  1 = collections\n"
                                    "                                  2 = items (default)\n"
                                    "                                  3 = attributes\n"
                                    "                                  4 = secrets");
        detail_opt.set_arg_description("N");
        main_group.add_entry(detail_opt, detail);

        unlock_opt.set_flags(OEF_IN_MAIN);
        unlock_opt.set_long_name("unlock");
        unlock_opt.set_short_name('u');
        unlock_opt.set_description("Unlock secrets.");
        main_group.add_entry(unlock_opt, unlock_flag);

        version_opt.set_flags(OEF_IN_MAIN);
        version_opt.set_long_name("version");
        version_opt.set_short_name('v');
        version_opt.set_description("Print version number and exit.");
        main_group.add_entry(version_opt, version_flag);

        add_option_group(main_group);
    }


    void
    on_activate()
        override
    {
        if (version_flag) {
            cout << PACKAGE_STRING << endl;
            return;
        }

        try {
            print();
        }
        catch (std::exception& e) {
            cerr << "Error: " << e.what() << endl;
            quit();
        }
    }


    void
    print()
    {
        cout << std::boolalpha;

        GError* service_error = nullptr;
        int flags = SECRET_SERVICE_LOAD_COLLECTIONS;
        if (detail >= Detail::Secrets)
            flags |= SECRET_SERVICE_OPEN_SESSION;

        service = take(secret_service_get_sync(SecretServiceFlags(flags),
                                               nullptr,
                                               &service_error));
        if (service_error)
            throw_error(service_error);


        cout << "Service\n";
        cout << "  Path: "
             << g_dbus_proxy_get_object_path(*service)
             << '\n';

        // check known aliases
        const std::vector<std::string> known_aliases{
            "default", "login", "session"
        };
        std::map<std::string, std::string> aliases;
        std::multimap<std::string, std::string> reverse_aliases;
        for (const auto& alias : known_aliases) {
            auto path = to_string(secret_service_read_alias_dbus_path_sync(*service,
                                                                           alias.c_str(),
                                                                           nullptr,
                                                                           nullptr));
            if (path) {
                aliases[alias] = *path;
                reverse_aliases.emplace(*path, alias);
            }
        }
        if (!aliases.empty()) {
            cout << "  Aliases:\n";
            for (auto& [alias, path] : aliases)
                cout << "    "
                     << alias
                     << ": "
                     << path
                     << '\n';
        }

        cout << '\n';

        if (detail < Detail::Collections)
            return;

        auto collections = to_vector<SecretCollection>(secret_service_get_collections(*service));
        for (auto& col : collections) {
            print(col, reverse_aliases, "    ");
            cout << '\n';
        }

    }


    void
    print(GObjectWrapper<SecretCollection>& col,
          const std::multimap<std::string, std::string>& reverse_aliases,
          const std::string& indent)
    {
        auto label = to_string(secret_collection_get_label(col));
        cout << indent
             << "Collection: \""
             << label.value()
             << "\"\n";

        cout << indent
             << "  Path: "
             << g_dbus_proxy_get_object_path(col)
             << '\n';

        // check if there's an alias for this collection
        auto path = g_dbus_proxy_get_object_path(col);
        auto range = reverse_aliases.equal_range(path);
        for (auto& i = range.first; i != range.second; ++i)
            cout << indent
                 << "  Alias: "
                 << i->second
                 << '\n';

        auto created = secret_collection_get_created(col);
        if (created)
            cout << indent
                 << "  Created: "
                 << timestamp_to_string(created).value()
                 << '\n';

        auto modified = secret_collection_get_modified(col);
        if (modified)
            cout << indent
                 << "  Modified: "
                 << timestamp_to_string(modified).value()
                 << '\n';

        if (unlock_flag && secret_collection_get_locked(col)) {
            auto error = unlock(col);
            if (error)
                cout << indent << "  Error: " << error->what() << endl;
        }
        bool locked = secret_collection_get_locked(col);
        cout << indent << "  Locked: " << locked << '\n';

        cout << '\n';

        if (detail < Detail::Items)
            return;

        auto items = to_vector<SecretItem>(secret_collection_get_items(col));
        for (auto& item : items) {
            print(item, indent + "    ");
            cout << '\n';
        }

    }


    void
    print(GObjectWrapper<SecretItem>& item,
          const std::string& indent)
    {
        auto label = to_string(secret_item_get_label(item));
        cout << indent
             << "Item: \""
             << label.value()
             << "\"\n";

        cout << indent
             << "  Path: "
             << g_dbus_proxy_get_object_path(item)
             << '\n';

        auto created = secret_item_get_created(item);
        if (created)
            cout << indent
                 << "  Created: "
                 << timestamp_to_string(created).value()
                 << '\n';

        auto modified = secret_item_get_modified(item);
        if (modified)
            cout << indent
                 << "  Modified: "
                 << timestamp_to_string(modified).value()
                 << '\n';

        if (detail < Detail::Attributes)
            return;

        auto attributes = to_map(secret_item_get_attributes(item));
        if (!attributes.empty()) {
            static const std::string attrib_indent = indent + "    ";
            cout << indent << "  Attributes:\n";
            for (auto& [key, val] : attributes) {
                cout << attrib_indent
                     << "  \""
                     << key
                     << "\" = \""
                     << val
                     << "\"\n";
            }
        }

        auto print_locked = [&item, indent] {
            bool locked = secret_item_get_locked(item);
            cout << indent << "  Locked: " << locked << '\n';
        };

        if (unlock_flag && secret_item_get_locked(item)) {
            auto error = unlock(item);
            print_locked();
            if (error) {
                cout << indent << "  Error: " << error->what() << endl;
                return;
            }
        } else
            print_locked();

        if (detail < Detail::Secrets)
            return;

        GError* error = nullptr;
        if (!secret_item_load_secret_sync(item, nullptr, &error)) {
            cout << indent << "  Error: " << to_error(error).what() << endl;
            return;
        }

        auto val = secret_item_get_secret(item);
        if (val) {
            cout << indent << "  Secret:\n";

            auto type = secret_value_get_content_type(val);
            cout << indent
                 << "    Type: "
                 << type
                 << '\n';

            auto text = secret_value_get_text(val);
            if (text) {
                cout << indent
                     << "    Value: \""
                     << text
                     << "\"\n";
            } else {
                gsize len = 0;
                auto ptr = secret_value_get(val, &len);
                auto repr = to_string(ptr, len);
                cout << indent
                     << "    Value: { "
                     << repr
                     << " } (hex)\n";
            }

            secret_value_unref(val);
        } else {
            cout << indent
                 << "  Error: secret is null\n";
        }
    }


    template<typename T>
    std::optional<std::runtime_error>
    unlock(GObjectWrapper<T>& obj)
    {
        GList* unlock_list = g_list_append(nullptr, obj.get());
        GError* error = nullptr;
        secret_service_unlock_sync(*service,
                                   unlock_list,
                                   nullptr,
                                   nullptr,
                                   &error);
        g_list_free(unlock_list);

        if (error)
            return to_error(error);

        return {};
    }

};


int
main(int argc, char *argv[])
{
    Gio::init();

    App app;
    return app.run(argc, argv);
}
