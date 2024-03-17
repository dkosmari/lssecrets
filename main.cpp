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
using std::cerr;
using std::endl;

using namespace std::literals;


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


    bool show_secrets = false;
    bool do_unlock = false;

    std::optional<GObjectWrapper<SecretService>> service;


    App() :
        Gio::Application{"lssecrets.dkosmari.github.com"}
    {
        add_main_option_entry(
#if HAVE_GLIBMM_2_68
                              OptionType::BOOL,
#else
                              OptionType::OPTION_TYPE_BOOL,
#endif
                              "secrets",
                              's',
                              "Show secret values.");
        add_main_option_entry(
#if HAVE_GLIBMM_2_68
                              OptionType::BOOL,
#else
                              OptionType::OPTION_TYPE_BOOL,
#endif
                              "unlock",
                              'u',
                              "Unlock secrets.");


        signal_handle_local_options().connect(sigc::mem_fun(*this, &App::handle_local_options),
                                              true);
    }



    int
    handle_local_options(const Glib::RefPtr<Glib::VariantDict>& options)
    {
        if (options->contains("secrets"))
            show_secrets = true;

        if (options->contains("unlock"))
            do_unlock = true;

        return -1; // means "continue processing options"
    }


    void
    on_activate()
        override
    {
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
        if (show_secrets)
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

        bool locked = secret_collection_get_locked(col);
        if (locked && do_unlock) {
            auto error = unlock(col);
            if (error)
                cout << indent << "  Error: " << error->what() << endl;
        }

        cout << '\n';

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

        bool locked = secret_item_get_locked(item);
        if (locked && do_unlock) {
            auto error = unlock(item);
            if (error) {
                cout << indent << "  Error: " << error->what() << endl;
                return;
            }
        }

        if (!show_secrets)
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
