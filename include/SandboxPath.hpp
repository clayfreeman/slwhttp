/**
 * @file  SandboxPath.hpp
 * @brief SandboxPath
 *
 * Class definition for SandboxPath
 *
 * @author     Clay Freeman
 * @date       December 1, 2015
 */

#ifndef _SANDBOXPATH_HPP
#define _SANDBOXPATH_HPP

#include <string>

class SandboxPath {
  private:
    static std::string jail;
    std::string rpath{};
  public:
    SandboxPath(const std::string& path);
    const std::string& get() const;
    static bool checkJail(std::string path);
    static bool setJail(const std::string& path);
};

#endif
