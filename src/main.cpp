/**
 * @file  main.cpp
 * @brief Secure Lightweight HTTP Server
 *
 * Lightweight executable that serves (read: dumps) static content from a
 * sandbox directory mimicking an extremely basic subset of the HTTP/1.0
 * protocol in a secure manner
 *
 * This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
 * International License. To view a copy of this license, visit:
 * http://creativecommons.org/licenses/by-sa/4.0/
 *
 * @author     Clay Freeman
 * @date       November 30, 2015
 */

// System-level header includes
#include <cassert>        // for assert
#include <cerrno>         // for errno, EBADF
#include <chrono>         // for seconds, duration, operator<, etc
#include <climits>        // for INT_MAX
#include <cstdint>        // for int64_t
#include <cstdio>         // for perror, SEEK_END, SEEK_SET
#include <cstdlib>        // for exit, EXIT_FAILURE, NULL, etc
#include <cstring>        // for memset
#include <fcntl.h>        // for fcntl, open, F_GETFD, O_RDONLY, etc
#include <iostream>       // for operator<<, basic_ostream, endl, etc
#include <mutex>          // for mutex, unique_lock
#include <netinet/in.h>   // for sockaddr_in, htons, INADDR_ANY, etc
#include <pwd.h>          // for getpwnam_r, passwd
#include <regex>          // for regex, regex_search, smatch
#include <signal.h>       // for signal, SIGPIPE, SIG_IGN
#include <stdexcept>      // for exception, runtime_error
#include <string>         // for string, allocator, operator+, etc
#include <sys/select.h>   // for select, FD_ISSET, FD_SET, etc
#include <sys/sendfile.h> // for sendfile64
#include <sys/socket.h>   // for SOL_SOCKET, AF_INET, accept, etc
#include <sys/time.h>     // for timeval
#include <sys/types.h>    // for size_t, ssize_t
#include <syslog.h>       // for openlog, syslog
#include <thread>         // for thread
#include <unistd.h>       // for close, lseek, fsync, read, etc
#include <vector>         // for vector

// User-level header includes
#include "ext/File/File.hpp"
#include "ext/Utility/Utility.hpp"
#include "include/SandboxPath.hpp"

// Set the default index path (from htdocs directory)
#define INDEX     "/index.html"
#define BUFSIZE   8192

// Declare function prototypes
void                     access_denied  (int fd, const std::string& message);
void                     begin          ();
void                     debug          (const std::string& str,
                                         bool error = false);
void                     dump_file      (int fd, const SandboxPath& path);
void                     prepare_socket ();
void                     print_help     (bool should_exit = true);
void                     process_request(int fd);
std::vector<std::string> read_request   (int fd);
bool                     ready          (int fd, int sec = 0, int usec = 0);
bool                     safe_sendfile  (int in_fd, int out_fd,
                                         int64_t data_length);
bool                     safe_write     (int fd, const std::string& data);
std::string&             urldecode      (std::string& url, bool extra = false);
inline bool              valid          (int fd);

// Declare storage for global configuration state
bool         _debug = false;
std::string _htdocs = "";
std::mutex   _mutex = {};
int           _port = 80;
int         _sockfd = -1;

int main(int argc, const char* argv[]) {
  // General assertions for reliability
  assert(File::realPath("/bin")    == "/bin");
  assert(File::realPath("/bin/.")  == "/bin");
  assert(File::realPath("/bin/..") == "/");

  // Ignore SIGPIPE (shouldn't be needed, just a precaution)
  signal(SIGPIPE, SIG_IGN);

  // Gather a vector of all arguments from argv[]
  std::vector<std::string> arguments{};
  for (int i = 1; i < argc; ++i)
    arguments.push_back(argv[i]);

  // Open a connection to the system logger for messages
  openlog(PACKAGE_NAME, LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_DAEMON);

  // Iterate over the options until no more arguments exist
  for (auto it = arguments.begin(); it != arguments.end(); ++it) {
    // Copy the argument from the arguments vector
    std::string option{*it};
    // Debug the option being processed
    debug("processing option: " + option);
    // Lowercase the text in the option variable
    Utility::strtolower(option);
    // Check if the given item is a valid option
    if (option == "--debug") {
      _debug = true;
      debug("all debug messages can be found in the syslog");
      debug("running in debug mode will reduce performance");
    }
    else if (option == "--help")
      print_help();
    else if (option == "--port") {
      if (it + 1 != arguments.end()) {
        try {
          // NOTE: cppcheck complains that it + 1 is not checked for equality
          //       against arguments.end(), but that check is three lines up...
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
    debug(e.what());
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
void access_denied(int fd, const std::string& message) {
  if (valid(fd)) {
    // Build the response variable
    std::string response{
      "HTTP/1.0 403 Forbidden\r\n"
      "Content-Length: " + std::to_string(message.length()) + "\r\n"
      "\r\n" +
      message
    };
    // Write response to client
    safe_write(fd, response);
  }
}

/**
 * @brief Begin
 *
 * Begin listening for connections
 */
void begin() {
  // Prepare the listening socket in order to accept connections
  prepare_socket();

  // Set the effective user/group ID to "nobody"
  struct passwd* tent = nullptr;
  struct passwd entry;
  // Ensure the entry is zero-initialized
  memset(&entry, 0, sizeof(struct passwd));
  char entry_buf[256] = {};
  if (getpwnam_r("nobody", &entry, entry_buf, sizeof(entry_buf), &tent) != 0)
    throw std::runtime_error{"could not find UID/GID for user \"nobody\" "};
  if (getgid() == 0 || getuid() == 0) {
    // Set the real GID/UID if running as root to prevent gaining root access
    if (setgid(entry.pw_gid) != 0 || setuid(entry.pw_uid) != 0)
      throw std::runtime_error{"failed to set UID/GID to user \"nobody\""};
  }
  else if (setegid(entry.pw_gid) != 0 || seteuid(entry.pw_uid) != 0)
    // Otherwise, set the effective GID/UID in order to preserve process
    // ownership (to allow killing your own daemon)
    throw std::runtime_error{"failed to set eUID/eGID to user \"nobody\" "
      "(not running as root?)"};

  // Inform the user of privilege drop
  debug("now running with reduced privileges of 'nobody' account");

  // Drop to a daemon process
  if (daemon(0, 0) != 0) {
    debug("couldn't daemonize", true);
    exit(EXIT_FAILURE);
  }

  // Loop indefinitely to accept and process clients
  debug("begin accepting clients securely");
  while (valid(_sockfd)) {
    // Stall for incoming connections or data
    ready(_sockfd, INT_MAX);
    // If the listening socket is marked as read available, client incoming
    int clifd = accept(_sockfd, NULL, NULL);
    // Check if the client descriptor is valid
    if (valid(clifd)) {
      debug("accepted client: " + std::to_string(clifd));
      // Process the request
      std::thread(process_request, clifd).detach();
    }
    else debug("error accepting client", true);
  }
}

/**
 * @brief Debug
 *
 * Prints debug information if debug mode is enabled
 *
 * @param  str    The input string
 * @param  error  Whether or not this call should print using perror(...)
 */
void debug(const std::string& str, bool error) {
  // Check if debug mode is enabled
  if (_debug == true) {
    std::unique_lock<std::mutex> lock{_mutex};
    if (error == true)
      // Print the given message with the appropriate error string
      syslog(LOG_DEBUG, "%s: %s", str.c_str(), strerror(errno));
    else
      // Print the given message
      syslog(LOG_DEBUG, "%s",     str.c_str());
  }
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
  // Ensure the output fd is valid
  if (valid(fd)) {
    // Open file for reading
    int file = open(path.get().c_str(), O_RDONLY);
    // Ensure the file was successfully opened and is in good condition
    if (valid(file)) {
      // Calculate the file size
      int64_t fsize = lseek64(file, 0, SEEK_END);
      if (fsize >= 0 && lseek64(file, 0, SEEK_SET) >= 0) {
        // Write response to client
        const std::string response{
          "HTTP/1.0 200 OK\r\n"
          "Content-Length: " + std::to_string(fsize) + "\r\n"
          "\r\n"
        };

        // Dump the response to the client
        debug("attempting to send " + std::to_string(fsize) + " byte file to "
          "client: " + std::to_string(fd));
        safe_write(fd, response);
        safe_sendfile(file, fd, fsize);
      }
    }
    // Close the source file
    close(file);
  }
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
    throw std::runtime_error{"failed to set socket option SO_REUSEADDR"};
  struct timeval timeout{3, 0};
  if (setsockopt(_sockfd, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout,
      sizeof(struct timeval)) < 0)
    throw std::runtime_error{"failed to set socket option SO_RCVTIMEO"};
  if (setsockopt(_sockfd, SOL_SOCKET, SO_SNDTIMEO, (void*)&timeout,
      sizeof(struct timeval)) < 0)
    throw std::runtime_error{"failed to set socket option SO_SNDTIMEO"};
  // Attempt to bind to the listen address
  if (bind(_sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    close(_sockfd);
    throw std::runtime_error{"failed to bind to 0.0.0.0:" +
      std::to_string(_port)};
  }
  else {
    // Listen with a backlog of 256
    if (listen(_sockfd, 256) < 0) {
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
  std::cerr << "Usage: " << PACKAGE_NAME << " [OPTIONS] PATH" << std::endl
            << "Serves static content (securely) from a given directory."
            << std::endl << std::endl
            << "Command line options:" << std::endl
            << "  --debug    enable debug mode" << std::endl
            << "  --help     display this help and exit" << std::endl
            << "  --port     set the listen port (default: 80)" << std::endl
            << std::endl
            << "Examples:" << std::endl
            << "  " << PACKAGE_NAME << " --port 8080 /var/www" << std::endl
            << "  " << PACKAGE_NAME << " --help" << std::endl
            << "  " << PACKAGE_NAME << " --debug /var/www" << std::endl
            << std::endl
            << PACKAGE_NAME << "-" << PACKAGE_VERSION << " online help: <"
            << PACKAGE_URL << ">"
            << std::endl;
  if (should_exit == true)
    exit(EXIT_SUCCESS);
}

/**
 * @brief Process Request
 *
 * Takes a file descriptor and fetches a std::string request and processes the
 * text as the HTTP protocol
 *
 * @param  fd  The file descriptor of the associated client
 */
void process_request(int fd) {
  // Ensure that the provided fd is valid
  if (valid(fd)) {
    debug("process_request(" + std::to_string(fd) + ")");
    // Read the request headers provided by the client
    std::vector<std::string> request = read_request(fd);
    if (_debug == true) {
      debug("request content (from fd: " + std::to_string(fd) + "):");
      bool first = true;
      for (const std::string& line : request)
        if (first == true) {
          first = false;
          debug(" -> " + line);
        }
        else
          debug("    " + line);
    }
    // Check for GET request
    for (std::string line : request) {
      // Explode the line into words
      std::vector<std::string> words = Utility::explode(
        Utility::trim(line), " ");
      // Check for "GET" request
      if (words.size() > 0 && Utility::strtolower(words[0]) == "get") {
        // Determine htdocs relative request path
        std::string _rpath{};
        if (words.size() == 1 || Utility::trim(words[1]) == "/")
          // If there was no path provided, or the root was requested, serve
          // the INDEX macro from htdocs
          _rpath = INDEX;
        else
          // If a non-redirectable path was provided, use it
          _rpath = words[1];

        try {
          // Determine absolute request path
          _rpath = _htdocs + "/" + urldecode(_rpath);
          debug("raw request for path: " + _rpath);
          SandboxPath path{_rpath};
          debug("sandboxed request for real path (from fd: " +
            std::to_string(fd) + "): " + path.get());
          // Attempt to dump the file to the client
          dump_file(fd, path);
        } catch (const std::exception& e) {
          access_denied(fd, "Access denied to the requested path.\r\n");
          debug(e.what());
        }
      }
    }

    // Close the file descriptor
    shutdown(fd, SHUT_RDWR);
    close(fd);
    // Remove the file descriptor from the client set
    debug("disconnect fd: " + std::to_string(fd));
  }
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
  std::string request{};
  // Loop until empty line as per HTTP protocol
  auto start_time = std::chrono::high_resolution_clock::now();
  while (request.find("\n\n") == std::string::npos) {
    // Verify appropriate conditions before attempting to service request
    auto timediff = std::chrono::high_resolution_clock::now() - start_time;
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(timediff);
    if (duration < std::chrono::duration<int>{3} && valid(fd)) {
      // Determine if the client is readable with a delay of 10 ms
      if (ready(fd, 0, 10000)) {
        // Prepare a buffer for the incoming data
        unsigned char buffer[BUFSIZE] = {};
        // Read up to (BUFSIZE - 1) bytes from the file descriptor to ensure a
        // null character at the end to prevent overflow
        ssize_t data_read = read(fd, buffer, BUFSIZE - 1);
        if (data_read > 0) {
          // NULL the character following the last byte that was read
          buffer[data_read] = 0;
          // Copy the buffer into a std::string
          std::string req{reinterpret_cast<const char*>(buffer)};
          // Ensure only newline characters are in the reponse, not CRLF
          // (canonicalizes requests so that only LF may be used)
          for (auto loc = req.find("\r\n"); loc != std::string::npos;
              loc = req.find("\r\n", ++loc))
            req.replace(loc, 2, "\n");
          // Append req to the request headers
          request += req;
        }
        else if (data_read == 0) {
          // The client has disconnected if marked as readable, but no data was
          // received from it
          request.clear();
          break;
        }
      }
    }
    else {
      // The client failed to write a complete set of request headers in the
      // required time or its file descriptor became invalid
      request.clear();
      break;
    }
  }
  return Utility::explode(Utility::trim(request), "\n");
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
bool ready(int fd, int sec, int usec) {
  // Setup storage to determine if fd is readable
  fd_set rfds;
  FD_ZERO(&rfds);
  // Ensure a valid clifd
  if (valid(fd))
    FD_SET(fd, &rfds);
  // Declare an immediate timeout
  struct timeval timeout{sec, usec};
  // Use select to determine status
  select(fd + 1, &rfds, NULL, NULL, &timeout);
  return FD_ISSET(fd, &rfds);
}

/**
 * Safely copies the contents of the given input file descriptor to the given
 * output file descriptor
 *
 * The provided input file descriptor is accessed read-only for writing to the
 * provided output file descriptor using `sendfile64` in a loop until the
 * requested data length has been written (except in the case of an error)
 *
 * This function guarantees a supported size of 8EiB minus 1 byte as per the
 * standard implementation for `int64_t` (using multiple calls to `sendfile64`)
 *
 * @param  in_fd        The file descriptor to which the data will be written
 * @param  out_fd       The data that should be written
 * @param  data_length  The amount of data to write (input size)
 *
 * @return              true if successful, otherwise false
 */
bool safe_sendfile(int in_fd, int out_fd, int64_t data_length) {
  int64_t data_sent    = 0;
  ssize_t return_val   = 0;
  // Loop while there is data remaining and sendfile(...) succeeds
  while (return_val >= 0 && data_sent < data_length)
    // Attempt to copy a chunk of data and record the amount written
    return_val = sendfile64(out_fd, in_fd, &data_sent, data_length - data_sent);
  return (data_sent == data_length);
}

/**
 * Safely writes the given data to a file descriptor
 *
 * The provided data is accessed read-only for writing to the provided file
 * descriptor using networking best practices such as looping until all data is
 * written (except in the case of an error) and using `unsigned char` to
 * correctly represent binary data
 *
 * This function guarantees a supported size of 64KiB minus 1 byte as per the
 * standard for `size_t`, but probably supports a greater size depending on your
 * operating system's implementation
 *
 * @param  fd    The file descriptor to which the data will be written
 * @param  data  The data that should be written
 *
 * @return       true if successful, otherwise false
 */
bool safe_write(int fd, const std::string& data) {
  const unsigned char* data_buf = reinterpret_cast<const unsigned char*>(
                                  data.data());
   size_t  data_length = data.length();
   size_t  data_sent   = 0;
  ssize_t  return_val  = 0;
  // Loop while there is data remaining and write(...) succeeds
  while (return_val >= 0 && data_sent < data_length) {
    // Attempt to write a chunk of data and record the amount written
    return_val = write(fd, data_buf + data_sent, data_length - data_sent);
    if (return_val >= 0)
      // Increase the data_sent count by data_written on this iteration
      data_sent += static_cast<size_t>(return_val);
  }
  return (data_sent == data_length);
}

/**
 * Percent-decodes a given string using the format described in RFC 3986 § 2.1
 *
 * This method attempts to find and replace all patterns matching a percent
 * character followed by two hexadecimal characters (ranging from '0' to '9' and
 * 'A' to 'F') with an ASCII character represented by the hexadecimal value
 *
 * @param[out]  url    An input that might contain one or more percent-encoded
 *                     characters representing an ASCII value
 * @param       extra  Whether or not plus characters ('+') should be converted
 *                     to space characters (' ') before standard decoding occurs
 *
 * @return             The percent-decoded result containing its respective
 *                     ASCII substitutions for percent-encoded characters
 */
std::string& urldecode(std::string& url, bool extra) {
  // Optionally replace plus characters ('+') with a space character (' ')
  // before decoding according to the standard
  if (extra) std::regex_replace(url, std::regex{"+"}, " ");
  // Define a pattern that matches any percent character followed by two
  // hexadecimal characters (as per RFC 3986 § 2.1)
  const std::regex  pattern{"\x25([0-9A-F]{2})", std::regex_constants::icase};
  // Create storage to store each pattern match
  std::smatch match{};
  // Continue to search until no further matches occur
  while(std::regex_search(url, match, pattern))
    { // Fetch a pointer to the hexadecimal string
    const char* hex = match[1].str().c_str();
    // Convert the hexadecimal string to an ASCII character
    char dec = static_cast<char>(strtol(hex, nullptr, 16));
    // Perform a substitution of the original match with the decoded character
    // in the original URL
    url.replace(match.position(0), match.length(0), 1, dec); }
  // Return a reference to the original parameter
  return url;
}

/**
 * Determines if a file descriptor is considered valid for read, write, or other
 * input/output operations
 *
 * A file descriptor is considered invalid if a call requesting its flags fails
 * with the return value of `-1` or `errno` is set to `EBADF` (the provided
 * argument is not an open file descriptor). If neither case is satisfied, the
 * file descriptor is considered valid
 *
 * @param  fd  File descriptor that should be verified
 *
 * @return     `true` if the file descriptor is valid, `false` otherwise
 */
inline bool valid(int fd) {
  return (fcntl(fd, F_GETFD) != -1 || errno != EBADF);
}
