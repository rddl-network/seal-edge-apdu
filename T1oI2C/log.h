/**
 * Copyright (c) 2020, Michael Grand
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#define LOG_E(...) log_log(0, __FILE__, __LINE__, __VA_ARGS__)   
#define LOG_D(...) log_log(0, __FILE__, __LINE__, __VA_ARGS__)   
#define LOG_W(...) log_log(0, __FILE__, __LINE__, __VA_ARGS__)   


#define ENSURE_OR_GO_EXIT(test) if(!(test)) goto exit;

void log_log(int level, const char *file, int line, const char *fmt, ...);

#endif //__LOG_H__
