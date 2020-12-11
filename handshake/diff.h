#ifndef __DIFF_H__
#define __DIFF_H__

#include <dlfcn.h>

#if defined(__has_include)
#if __has_include(<sanitizer / coverage_interface.h>)
#include <sanitizer/coverage_interface.h>
#endif
#if __has_include(<sanitizer / lsan_interface.h>)
#include <sanitizer/lsan_interface.h>
#endif
#endif

#define NO_SANITIZE_MEMORY
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#undef NO_SANITIZE_MEMORY
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
#endif
#endif


// Use dynamic loading of independent libraries to accommodate libraries that
// use the same API names.
void *get_interface_fn(void *handle, const char *libpath, const char *fname) {
  void *generic_fp;
  char *error;

  handle = dlopen(libpath, RTLD_LAZY);
  if (!handle) {
    DBG("cannot load library: %s\n", dlerror());
    return NULL;
  }

  generic_fp = dlsym(handle, fname);
  if ((error = dlerror()) != NULL)  {
    DBG("cannot resolve function: %s\n", error);
    return NULL;
  }

  return generic_fp;
}


#endif // __DIFF_H__
