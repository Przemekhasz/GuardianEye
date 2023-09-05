#include "CustomValidator.hpp"

CustomValidator::CustomValidator(const std::string& name, int minLength, int maxLength, int rangeFrom, int rangeTo)
    : argName(name), minLength(minLength), maxLength(maxLength), rangeFrom(rangeFrom), rangeTo(rangeTo) {}

bool CustomValidator::validate(const std::string& argument) const {
    int argLength = static_cast<int>(argument.length());
    int argValue = std::stoi(argument);

    if (argLength < minLength || argLength > maxLength) {
        std::cout << "Argument " << argName << " must have length between " << minLength << " and " << maxLength << "." << std::endl;
        return false;
    }
    
    if (argLength < rangeFrom || argLength > rangeTo) {
        std::cout << "Argument " << argName << " must be in the range [" << rangeFrom << ", " << rangeTo << "]." << std::endl;
        return false;
    }
    return true;
}
