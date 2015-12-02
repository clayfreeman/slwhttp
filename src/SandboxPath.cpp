/**
 * @file  SandboxPath.cpp
 * @brief SandboxPath
 *
 * Class implementation for SandboxPath
 *
 * @author     Clay Freeman
 * @date       December 1, 2015
 */

#include <stdexcept>
#include <string>
#include "../ext/File/File.hpp"
#include "../include/SandboxPath.hpp"

// Initialize static members
std::string SandboxPath::jail{};

/**
 * @brief SandboxPath Constructor
 *
 * Constructs a safe SandboxPath to ensure jailed access to files
 *
 * @param  path  The input path
 */
SandboxPath::SandboxPath(const std::string& path) {
  // Yell at the user if there is no jail path set
  if (SandboxPath::jail.length() == 0)
    throw std::runtime_error{"no jail set for SandboxPath"};
  // Get the real path of the provided path
  std::string _rpath = File::realPath(path);
  // Check that the resulting path is within the sandbox
  if (SandboxPath::checkJail(_rpath))
    this->rpath = _rpath;
  else
    throw std::runtime_error{"checkJail(...) = false"};
}

/**
 * @brief Get
 *
 * Fetches the resulting path as a std::string
 *
 * @return  std::string path
 */
const std::string& SandboxPath::get() const {
  if (!File::isFile(this->rpath) || !File::readable(this->rpath))
    throw std::runtime_error{"\"" + this->rpath + "\" is not a readable file"};
  return this->rpath;
}

/**
 * @brief Set Jail
 *
 * Sets the jail for all SandboxPath objects
 *
 * @param  path  The input path
 *
 * @return       true if valid, otherwise false
 */
bool SandboxPath::setJail(const std::string& path) {
  if (SandboxPath::jail.length() == 0)
    SandboxPath::jail = File::realPath(path);
  return SandboxPath::jail.length() > 0;
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
bool SandboxPath::checkJail(std::string path) {
  bool valid = false;
  // Verify length constraints
  if (path.length() > SandboxPath::jail.length() + 1) {
    // Trim the string to the valid length
    path = path.substr(0, SandboxPath::jail.length() + 1);
    // Verify that the most significant path components match the sandbox
    if (path == SandboxPath::jail + "/")
      valid = true;
  }
  return valid;
}
