/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_CONFIG_HPP_
#define AOS_CORE_CONFIG_HPP_

/**
 * File/directory path len.
 */
#define AOS_CONFIG_FILE_PATH_LEN 512

/**
 * URL len.
 */
#define AOS_CONFIG_URL_LEN 4096

/**
 * Max number of node's resources.
 *
 * 既定は 4。resources.cfg に 5 個目を書いた時点で SM がノード情報を送れなくなり
 * （resourcemanager.cpp の PushBack が eNoMemory を返す）、CM 側からは
 * `node not found` と `UNIQUE constraint failed: launcher_instances` の繰り返しに
 * しか見えない。dri / usbcam / container-hosts / can / kuksa で既に 5 個ある。
 * SM と CM が同じ値で組まれている必要があるため、ここで全体に効かせる（2026-09-23）。
 */
#define AOS_CONFIG_TYPES_MAX_NUM_NODE_RESOURCES 8

#endif
