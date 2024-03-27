#pragma once

#include "paper/shared/logger.hpp"

//#define LOG_INFO(str...)
#define LOG_INFO(str, ...) Paper::Logger::fmtLogTag<Paper::LogLevel::INF>(str, MOD_ID __VA_OPT__(, __VA_ARGS__))
//#define LOG_DEBUG(str...)
#define LOG_DEBUG(str, ...) Paper::Logger::fmtLogTag<Paper::LogLevel::DBG>(str, MOD_ID __VA_OPT__(, __VA_ARGS__))
//#define LOG_ERROR(str...)
#define LOG_ERROR(str, ...) Paper::Logger::fmtLogTag<Paper::LogLevel::ERR>(str, MOD_ID __VA_OPT__(, __VA_ARGS__))
//#define LOG_CRITICAL(str...)
#define LOG_CRITICAL(str, ...) Paper::Logger::fmtLogTag<Paper::LogLevel::CRIT>(str, MOD_ID __VA_OPT__(, __VA_ARGS__))