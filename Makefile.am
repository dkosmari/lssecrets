EXTRA_DIST = \
	bootstrap \
	README.md


AM_CXXFLAGS = \
	-Wall -Wextra


AM_CPPFLAGS = \
	$(LIBSECRET_CFLAGS) \
	$(GLIBMM_CFLAGS) \
	-DSECRET_API_SUBJECT_TO_CHANGE


LIBS = \
	$(LIBSECRET_LIBS) \
	$(GLIBMM_LIBS)


bin_PROGRAMS = lssecrets


lssecrets_SOURCES = main.cpp

