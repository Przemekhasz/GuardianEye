#ifndef CUSTOM_VALIDATOR_H
#define CUSTOM_VALIDATOR_H

#include <iostream>
#include <string>

class CustomValidator {
public:
    CustomValidator(const std::string& name, int minLength, int maxLength, int rangeFrom, int rangeTo);

    bool validate(const std::string& argument) const;

private:
    std::string argName;
    int minLength;
    int maxLength;
    int rangeFrom;
    int rangeTo;
};

#endif
