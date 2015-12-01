/**
 * @file  main.cpp
 * @brief Secure Lightweight HTTP Server
 *
 * Lightweight executable that serves (read: dumps) static content from a
 * sandbox directory mimicking an extremely basic subset of the HTTP version
 * 1.0 protocol in a secure manner
 *
 * @author     Clay Freeman
 * @date       November 30, 2015
 */

#include <algorithm>    // std::transform(...)
#include <arpa/inet.h>  // inet_addr(...)
#include <cassert>      // assert(...)
#include <cctype>       // tolower(...)
#include <cerrno>       // perror(...)
#include <climits>      // realpath(...), PATH_MAX
#include <cstdio>       // perror(...)
#include <cstdlib>      // free(...), realpath(...)
#include <cstring>      // memset(...)
#include <fcntl.h>      // fcntl(...)
#include <iostream>     // std::cerr, std::endl
#include <netinet/ip.h> // socket(...)
#include <pwd.h>        // getpwnam(...)
#include <stdexcept>    // std::runtime_error
#include <string>       // std::string
#include <sys/socket.h> // bind(...), listen(...)
#include <sys/stat.h>   // stat(...)
#include <sys/time.h>   // timeval
#include <sys/types.h>  // stat(...)
#include <unistd.h>     // access(...), stat(...)
#include <vector>       // std::vector<...>

// Set the default index path (from htdocs directory)
#define INDEX "/index.html"

// Declare function prototypes
void        begin       ();
bool        check_jail  (std::string path);
inline void debug       (const std::string& str);
inline bool directory   (const std::string& path);
inline bool executable  (const std::string& path);
inline bool file        (const std::string& path);
inline void lowercase   (std::string& str);
void        print_help  (bool should_exit = true);
inline bool readable    (const std::string& path);
std::string real_path   (const std::string& path);

// Declare storage for global configuration state
bool         _debug = false;
std::string _htdocs = "";
std::string   _path = "";
int           _port = 80;

// Declare classes
class SandboxPath {
  private:
    std::string rpath{};
  public:
    SandboxPath(const std::string& path) {
      std::string _rpath = real_path(path);
      // Check that the resulting path is within the sandbox and has valid
      // permissions
      if (check_jail(_rpath)) {
        this->rpath = _rpath;
        debug("check_jail(\"" + _rpath + "\") = true");
      }
      else {
        this->rpath = _htdocs + INDEX;
        debug("check_jail(\"" + _rpath + "\") = false");
        debug("overriding rpath to \"" + this->rpath + "\" ...");
      }
    }
    const std::string& get() const {
      if (!file(this->rpath) || !readable(this->rpath))
        throw std::runtime_error{"\"" + this->rpath + "\" is not a readable " +
          "file"};
      return this->rpath;
    }
};

int main(int argc, const char* argv[]) {
  // General assertions for reliability
  assert(real_path("/bin")    == "/bin");
  assert(real_path("/bin/.")  == "/bin");
  assert(real_path("/bin/..") == "/");

  // Gather a vector of all arguments from argv[]
  if (argc > 0) _path = argv[0];
  std::vector<std::string> arguments{};
  for (int i = 1; i < argc; ++i)
    arguments.push_back(argv[i]);

  // Iterate over the options until no more arguments exist
  for (auto it = arguments.begin(); it != arguments.end(); ++it) {
    // Copy the argument from the arguments vector
    std::string option{*it};
    // Lowercase the text in the option variable
    lowercase(option);
    // Check if the given item is a valid option
    if (option == "--debug")
      _debug = true;
    else if (option == "--help")
      print_help();
    else if (option == "--port") {
      if (it + 1 != arguments.end()) {
        try {
          _port = std::stoi(*(++it));
          debug("_port = " + std::to_string(_port));
        } catch (const std::exception& e) {
          std::cerr << "Error: the provided port is not numeric" << std::endl;
          exit(EXIT_FAILURE);
        }
      }
      else {
        std::cerr << "Error: no port was provided" << std::endl;
        exit(EXIT_FAILURE);
      }
    }
    else if (_htdocs.length() == 0) {
      const std::string rpath = real_path(*it);
      if (directory(rpath) && executable(rpath)) {
        _htdocs = rpath;
        debug("_htdocs = " + _htdocs);
      }
      else {
        std::cerr << "Error: could not traverse htdocs path" << std::endl;
        exit(EXIT_FAILURE);
      }
    }
  }

  // Check that the sandbox argument was specified
  if (_htdocs.length() == 0) {
    std::cerr << "Error: htdocs directory not specified" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Begin listening for connections
  try {
    begin();
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    exit(EXIT_FAILURE);
  }

  return 0;
}

/**
 * @brief Begin
 *
 * Begin listening for connections
 */
void begin() {
  // Store the listening socket's file descriptor
  int sockfd = -1;

  // Wrap the listen logic in a block so that useless identifiers are freed
  {
    // Prepare the bind address information
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    serv_addr.sin_port        = htons(_port);

    // Setup the listening socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    // Attempt to bind to the listen address
    if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
      close(sockfd);
      throw std::runtime_error{"failed to bind to 0.0.0.0:" +
        std::to_string(_port)};
    }
    else {
      // Listen with a backlog of 1
      listen(sockfd, 1);
      debug("listening on 0.0.0.0:" + std::to_string(_port));
    }
  }

  // // Set the user and group ID to "nobody"
  // struct passwd* entry = getpwnam("nobody");
  // if (entry == NULL)
  //   throw std::runtime_error{"could not find UID/GID for user \"nobody\""};
  // if (setgid(entry->pw_gid) != 0 || setuid(entry->pw_uid) != 0)
  //   throw std::runtime_error{"failed to set UID/GID to user \"nobody\" "
  //     "(running as root?)"};

  // Loop indefinitely to accept and process clients
  while (true) {
    // debug("loop");

    // Setup storage to determine if a connection is incoming
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    struct timeval timeout{1, 0};
    // debug("select(...)");
    // Use select with a timeout of 0 to determine status
    select(sockfd + 1, &rfds, NULL, NULL, &timeout);

    // If the listening socket is marked as read available, client incoming
    if (FD_ISSET(sockfd, &rfds)) {
      // debug("incoming client");
      int clifd = accept(sockfd, NULL, NULL);
      // Check if the client descriptor is valid
      if (clifd >= 0) {
        debug("accepted client");

        // We've got a new client - process its request
        std::string request{};
        // Prepare a buffer for the incoming data
        char* buffer = (char*)calloc(8192, sizeof(char));
        // Read up to (8K - 1) bytes from the file descriptor to ensure a null
        // character at the end to prevent overflow
        read(clifd, buffer, 8191);
        // Copy the C-String into a std::string
        request += buffer;
        // Free the storage for the buffer ...
        free(buffer);

        close(clifd);
        debug("incoming request:\n\n" + request);
      }
    }
  }
}

/**
 * @brief Check Jail
 *
 * Checks that the given path is a child of the sandbox directory
 *
 * @param  path  The input string
 *
 * @return       true if valid, otherwise false
 */
bool check_jail(std::string path) {
  bool valid = false;
  // Verify length constraints
  if (path.length() > _htdocs.length() + 1) {
    // Trim the string to the valid length
    path = path.substr(0, _htdocs.length() + 1);
    // Verify that the most significant path components match the sandbox
    if (path == _htdocs + "/")
      valid = true;
  }
  return valid;
}

/**
 * @brief Debug
 *
 * Prints debug information if debug mode is enabled
 *
 * @param  str  The input string
 */
inline void debug(const std::string& str) {
  // Check if debug mode is enabled
  if (_debug == true)
    // Print the given message
    std::cerr << "[DEBUG] " << str << std::endl;
}

/**
 * @brief Directory
 *
 * Determines if a path is a directory
 *
 * @param  path       The input path
 *
 * @return            true if directory, otherwise false
 */
inline bool directory(const std::string& path) {
  struct stat buffer;
  return (stat(path.c_str(), &buffer) == 0 && buffer.st_mode & S_IFDIR);
}

/**
 * @brief Executable
 *
 * Determines if a path is executable
 *
 * @param  path       The input path
 *
 * @return            true if executable, otherwise false
 */
inline bool executable(const std::string& path) {
  return (access(path.c_str(), X_OK) == 0);
}

/**
 * @brief File
 *
 * Determines if a path is a file
 *
 * @param  path       The input path
 *
 * @return            true if file, otherwise false
 */
inline bool file(const std::string& path) {
  struct stat buffer;
  return (stat(path.c_str(), &buffer) == 0 && buffer.st_mode & S_IFREG);
}

/**
 * @brief Lowercase
 *
 * Transforms a string to contain lowercase-only alphabet characters
 *
 * @param  str  The input string
 *
 * @return      std::string containing the lowercase text
 */
inline void lowercase(std::string& str) {
  // Transform the provided string using the std::transform(...) and
  // tolower(...) functions
  std::transform(str.begin(), str.end(), str.begin(), ::tolower);
}

/**
 * @brief Print Help
 *
 * Prints help information and optionally calls exit(...)
 *
 * @param  should_exit  Bool saying whether or not the program should exit upon
 *                      completion of the function
 */
void print_help(bool should_exit) {
  std::cerr << "Usage: " << _path << " [OPTIONS] PATH" << std::endl
            << "Serves static content from the given directory." << std::endl
            << std::endl
            << "Command line options:" << std::endl
            << "  --debug    enable debug mode" << std::endl
            << "  --help     display this help and exit" << std::endl
            << "  --port     set the listen port (default: 80)" << std::endl
            << std::endl
            << "Examples:" << std::endl
            << "  " << _path << " --port 8080 /var/www" << std::endl
            << "  " << _path << " --help" << std::endl
            << "  " << _path << " --debug /var/www" << std::endl;
  if (should_exit == true)
    exit(EXIT_SUCCESS);
}

/**
 * @brief Readable
 *
 * Determines if a path is readable
 *
 * @param  path       The input path
 * @param  directory  Whether or not to test traversability (execute bit)
 *
 * @return            true if readable, otherwise false
 */
inline bool readable(const std::string& path) {
  return (access(path.c_str(), R_OK) == 0);
}

/**
 * @brief Real Path
 *
 * Fetches the absolute path for a given input path
 *
 * @param  path  The input path
 *
 * @return       std::string containing the absolute path or an empty on failure
 */
std::string real_path(const std::string& path) {
  // Create storage for the resulting path
  std::string return_value{};
  // Fetch the real path for the provided path
  char* rpath = realpath(path.c_str(), NULL);
  debug("realpath(\"" + path + "\", NULL) = " +
    (rpath == NULL ? "NULL" : std::string{rpath}));
  // Check if an error occurred
  if (rpath == NULL) {
    // Print the error to the console
    if (_debug == true)
      perror(("[DEBUG] " + path).c_str());
  }
  else {
    // No error occurred; build the return value
    return_value = std::string{rpath};
    // Free the provided resource from realpath(...)
    free(rpath);
  }
  // Null the rpath variable to prevent further use
  rpath = NULL;
  return return_value;
}
