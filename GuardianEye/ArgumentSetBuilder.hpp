#ifndef ARGUMENT_SET_BUILDER_H
#define ARGUMENT_SET_BUILDER_H

#include <iostream>
#include <string>
#include <vector>
#include "CustomValidator.hpp"

class ArgumentSetBuilder {
public:
    ArgumentSetBuilder& addArgument(const std::string& name, int minLength, int maxLength, int rangeFrom, int rangeTo);
    
    ArgumentSetBuilder& addArgumentSet(const std::vector<std::string>& args);
    
    void validateArguments();

private:
    std::vector<CustomValidator> validators;
    std::vector<std::vector<std::string> > argumentSets;
};

#endif
