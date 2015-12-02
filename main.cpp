/**
 * @file  main.cpp
 * @brief Secure Lightweight HTTP Server
 *
 * Lightweight executable that serves (read: dumps) static content from a
 * sandbox directory mimicking an extremely basic subset of the HTTP version
 * 1.0 protocol in a secure manner
 *
 * This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
 * International License. To view a copy of this license, visit:
 * http://creativecommons.org/licenses/by-sa/4.0/
 *
 * @author     Clay Freeman
 * @date       November 30, 2015
 */

#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <netinet/ip.h>
#include <pwd.h>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/sendfile.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "ext/File/File.hpp"
#include "ext/Utility/Utility.hpp"
#include "include/SandboxPath.hpp"

// Set the default index path (from htdocs directory)
#define INDEX "/index.html"

// Declare function prototypes
void                     access_denied  (int fd);
void                     begin          ();
inline void              debug          (const std::string& str);
void                     dump_file      (int fd, const SandboxPath& path);
void                     prepare_socket ();
void                     print_help     (bool should_exit = true);
void                     process_request(int fd);
std::vector<std::string> read_request   (int fd);
void                     ready          ();
bool                     ready          (int fd, int tout = 0);

// Declare storage for global configuration state
bool            _debug = false;
std::set<int> _clients = {};
std::string    _htdocs = "";
std::mutex      _mutex = {};
std::string      _path = "";
int              _port = 80;
int            _sockfd = -1;

int main(int argc, const char* argv[]) {
  // General assertions for reliability
  assert(File::realPath("/bin")    == "/bin");
  assert(File::realPath("/bin/.")  == "/bin");
  assert(File::realPath("/bin/..") == "/");

  // Ignore SIGPIPE
  signal(SIGPIPE, SIG_IGN);

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
    Utility::strtolower(option);
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
      const std::string rpath = File::realPath(*it);
      if (File::isDirectory(rpath) && File::executable(rpath)) {
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

  // Set the jail path for SandboxPath objects
  SandboxPath::setJail(_htdocs);

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
 * @brief Access Denied
 *
 * Writes a HTTP/1.0 403 error to the given client
 *
 * @param  fd  The file descriptor of the associated client
 */
void access_denied(int fd) {
  // Build the response variable
  std::string content{
    "Forbidden\r\n"
  };
  std::string response{
    "HTTP/1.0 403 Forbidden\r\n"
    "Content-Length: " + std::to_string(content.length()) + "\r\n"
    "\r\n" +
    content
  };
  // Write response to client
  write(fd, response.c_str(), response.length());
  fsync(fd);
}

/**
 * @brief Begin
 *
 * Begin listening for connections
 */
void begin() {
  // Prepare the listening socket in order to accept connections
  prepare_socket();

  // // Set the user and group ID to "nobody"
  // struct passwd* entry = getpwnam("nobody");
  // if (entry == NULL)
  //   throw std::runtime_error{"could not find UID/GID for user \"nobody\""};
  // if (setgid(entry->pw_gid) != 0 || setuid(entry->pw_uid) != 0)
  //   throw std::runtime_error{"failed to set UID/GID to user \"nobody\" "
  //     "(not running as root?)"};

  // Loop indefinitely to accept and process clients
  while (true) {
    // Stall for incoming connections or data
    ready();
    // If the listening socket is marked as read available, client incoming
    if (ready(_sockfd)) {
      int clifd = accept(_sockfd, NULL, NULL);
      // Check if the client descriptor is valid
      if (clifd >= 0) {
        debug("accepted client");
        // Add the client to the vector of clients
        std::unique_lock<std::mutex> lock(_mutex);
        debug("inserting fd:" + std::to_string(clifd));
        _clients.insert(clifd);
        lock.unlock();
      }
      else if (_debug == true)
        perror(("[DEBUG] Error " + std::to_string(errno)).c_str());
    }
    // Lock the mutex to reserve access to _clients
    std::unique_lock<std::mutex> lock(_mutex);
    // Check each client for available data
    for (int clifd : _clients) {
      // Check if data was sent by the client
      if (ready(clifd))
        // Process the request
        std::thread(process_request, clifd).detach();
    }
    lock.unlock();
  }
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
 * @brief Dump File
 *
 * Attempts to dump a file to a client file descriptor
 *
 * @param  path  A SanboxPath to the file to dump
 * @param  fd    The file descriptor to dump the file
 */
void dump_file(int fd, const SandboxPath& path) {
  // Open file for reading
  int file = open(path.get().c_str(), O_RDONLY);
  // Ensure the file was successfully opened and is in good condition
  if (file >= 0) {
    // Calculate the file size
    off_t fsize = lseek(file, 0, SEEK_END);
    if (fsize >= 0 && lseek(file, 0, SEEK_SET) >= 0) {
      // Write response to client
      const std::string response{
        "HTTP/1.0 200 OK\r\n"
        "Content-Length: " + std::to_string(fsize) + "\r\n"
        "\r\n"
      };

      // Dump the response to the client
      if (write(fd, response.c_str(), response.length()) < 0)
        perror("WRITE ERROR");
      if (sendfile(fd, file, 0, fsize) < 0)
        perror("WRITE ERROR");
    }
  }
  // Close the source file
  close(file);
  // Synchronize the output
  fsync(fd);
}

/**
 * @brief Prepare Socket
 *
 * Prepares the listening socket for accepting incoming connections
 */
void prepare_socket() {
  // Prepare the bind address information
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family      = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port        = htons(_port);

  // Setup the listening socket
  _sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (_sockfd < 0)
    throw std::runtime_error{"failed to create socket"};
  // Attempt to reuse the listen address if already (or was) in use
  int yes = 1;
  if (setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
    throw std::runtime_error{"failed to set socket option"};
  // Attempt to bind to the listen address
  if (bind(_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    close(_sockfd);
    throw std::runtime_error{"failed to bind to 0.0.0.0:" +
      std::to_string(_port)};
  }
  else {
    // Listen with a backlog of 1
    if (listen(_sockfd, 64) < 0) {
      close(_sockfd);
      throw std::runtime_error{"failed to listen on socket"};
    }
    debug("listening on 0.0.0.0:" + std::to_string(_port));
  }
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
 * @brief Process Request
 *
 * Takes a file descriptor and a std::string request and processes the text as
 * HTTP protocol
 *
 * @param  fd  The file descriptor of the associated client
 */
void process_request(int fd) {
  // Ensure the client has sent some data within three seconds
  if (ready(fd, 3)) {
    // Read the request headers provided by the client
    try {
      std::vector<std::string> request = read_request(fd);
      // Check for GET request
      for (std::string line : request) {
        // Explode the line into words
        std::vector<std::string> words = Utility::explode(line, " ");
        // Check for "GET" request
        if (words.size() > 0 && Utility::strtolower(words[0]) == "get") {
          // Determine htdocs relative request path
          std::string _rpath{};
          if (words.size() == 1 || words[1] == "/")
            // If there was no path provided, or the root was requested, serve
            // the INDEX macro from htdocs
            _rpath = INDEX;
          else
            // If a non-redirectable path was provided, use it
            _rpath = words[1];

          if (_rpath.find("/") == 0)
            // Remove the slash at the beginning of the request path
            _rpath = _rpath.substr(1);

          try {
            // Determine absolute request path
            _rpath = _htdocs + "/" + _rpath;
            debug("Request for absolute path: " + _rpath);
            SandboxPath path{_rpath};
            debug("Request for file: " + path.get());
            // Attempt to dump the file to the client
            dump_file(fd, path);
          } catch (const std::exception& e) {
            access_denied(fd);
            debug(e.what());
          }
        }
      }
    } catch (const std::exception& e) {
      debug(e.what());
    }
  }

  // Close the file descriptor
  shutdown(fd, SHUT_RDWR);
  close(fd);
  // Lock the mutex while modifying _clients
  std::unique_lock<std::mutex> lock(_mutex);
  // Remove the file descriptor from the client set
  debug("removing fd:" + std::to_string(fd));
  auto it = _clients.find(fd);
  if (it != _clients.end())
    _clients.erase(it);
  // Unlock the mutex
  lock.unlock();
}

/**
 * @brief Read Request
 *
 * Reads HTTP/1.0 request headers from the given client
 *
 * @param  fd  The file descriptor of the associated client
 *
 * @return     std::vector of request header lines
 */
std::vector<std::string> read_request(int fd) {
  std::vector<std::string> request{};
  // Loop until empty line as per HTTP protocol
  while (request.size() == 0 || request.back().length() > 0) {
    if (ready(fd, 3)) {
      // Prepare a buffer for the incoming data
      char* buffer = (char*)calloc(8192, sizeof(char));
      // Read up to (8K - 1) bytes from the file descriptor to ensure a null
      // character at the end to prevent overflow
      read(fd, buffer, 8191);
      // Copy the C-String into a std::string
      std::string req{buffer};
      // Free the storage for the buffer ...
      free(buffer);
      // Add each line of the buffer to the request vector
      for (std::string line : Utility::explode(req, "\n"))
        request.push_back(line);
    }
    else break;
  }
  return request;
}

/**
 * @brief Ready
 *
 * Calls select(...) for listening socket and all clients in order to stall for
 * incoming connections or data
 */
void ready() {
  // Setup storage to determine if anything is readable
  fd_set rfds;
  FD_ZERO(&rfds);
  if (fcntl(_sockfd, F_GETFD) != -1 || errno != EBADF)
    FD_SET(_sockfd, &rfds);
  // Add each client to the fd set
  int max = _sockfd;
  std::unique_lock<std::mutex> lock(_mutex);
  for (int clifd : _clients) {
    // Ensure a valid clifd
    if (fcntl(clifd, F_GETFD) != -1 || errno != EBADF) {
      FD_SET(clifd, &rfds);
      // Keep up with the maximum fd
      if (clifd > max)
        max = clifd;
    }
  }
  lock.unlock();
  // Declare a maximum timeout
  struct timeval timeout{INT_MAX, 0};
  // Use select to determine status
  select(max + 1, &rfds, NULL, NULL, &timeout);
  // throw std::runtime_error{"could not select(...)"};
}

/**
 * @brief Ready
 *
 * Determines if a specific file descriptor is ready for reading
 *
 * @param  fd  The file descriptor to test
 *
 * @return     true if ready, otherwise false
 */
bool ready(int fd, int tout) {
  // Setup storage to determine if fd is readable
  fd_set rfds;
  FD_ZERO(&rfds);
  // Ensure a valid clifd
  if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
    FD_SET(fd, &rfds);
  // Declare an immediate timeout
  struct timeval timeout{tout, 0};
  // Use select to determine status
  select(fd + 1, &rfds, NULL, NULL, &timeout);
  // throw std::runtime_error{"could not select(" + std::to_string(fd) + ")"};
  return FD_ISSET(fd, &rfds);
}
