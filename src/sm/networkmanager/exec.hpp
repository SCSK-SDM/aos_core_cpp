/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_SM_NETWORKMANAGER_EXEC_HPP_
#define AOS_SM_NETWORKMANAGER_EXEC_HPP_

#include <string>
#include <vector>

#include <core/common/tools/error.hpp>

namespace aos::sm::cni {
/**
 * Interface for executing plugins.
 */
class ExecItf {
public:
    /**
     * Executes a plugin.
     *
     * @param payload Plugin payload.
     * @param pluginPath Path to the plugin.
     * @param args Plugin arguments.
     * @return RetWithError<std::string>.
     */
    virtual RetWithError<std::string> ExecPlugin(
        const std::string& payload, const std::string& pluginPath, const std::string& args) const
        = 0;

    /**
     * Executes a command with arguments and returns its stdout.
     *
     * ExecPlugin() passes everything through the environment, as the CNI spec requires,
     * so it cannot run an ordinary command. Restoring a CAN link after host-device has
     * moved it needs "ip" with arguments.
     *
     * @param path Path to the executable.
     * @param args Arguments.
     * @return RetWithError<std::string>.
     */
    virtual RetWithError<std::string> ExecCommand(const std::string& path, const std::vector<std::string>& args) const
        = 0;
};

/**
 * Executes plugins.
 */
class Exec : public ExecItf {
public:
    /**
     * Executes a plugin.
     *
     * @param payload Plugin payload.
     * @param pluginPath Path to the plugin.
     * @param args Plugin arguments.
     * @return RetWithError<std::string>.
     */
    RetWithError<std::string> ExecPlugin(
        const std::string& payload, const std::string& pluginPath, const std::string& args) const override;

    /**
     * Executes a command with arguments and returns its stdout.
     *
     * @param path Path to the executable.
     * @param args Arguments.
     * @return RetWithError<std::string>.
     */
    RetWithError<std::string> ExecCommand(
        const std::string& path, const std::vector<std::string>& args) const override;
};

} // namespace aos::sm::cni

#endif // EXEC_HPP_
