AM_CXXFLAGS     = -std=c++11 -Wall -Wextra -pedantic

if ENABLE_SETUID
  AM_CXXFLAGS  += -DENABLE_SETUID
endif

bin_PROGRAMS    = slwhttp
slwhttp_SOURCES = main.cpp SandboxPath.cpp ext/File/File.cpp \
                  ext/Utility/Utility.cpp
slwhttp_LDADD   = -lpthread

if ENABLE_SETUID
install-exec-hook:
	chown root:root $(DESTDIR)$(bindir)/slwhttp
	chmod 4755      $(DESTDIR)$(bindir)/slwhttp
endif
