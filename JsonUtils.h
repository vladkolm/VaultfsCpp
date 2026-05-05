#pragma once

#include <string>

std::string JsonEscape(const std::wstring& value);
std::wstring JsonUnescapeToWide(const std::string& value);
