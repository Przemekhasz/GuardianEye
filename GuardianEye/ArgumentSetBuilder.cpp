#include "ArgumentSetBuilder.hpp"
#include <iostream>

ArgumentSetBuilder& ArgumentSetBuilder::addArgument(const std::string& name, int minLength, int maxLength, int rangeFrom, int rangeTo) {
    validators.push_back(CustomValidator(name, minLength, maxLength, rangeFrom, rangeTo));
    return *this;
}

ArgumentSetBuilder& ArgumentSetBuilder::addArgumentSet(const std::vector<std::string>& args) {
    argumentSets.push_back(args);
    return *this;
}

void ArgumentSetBuilder::validateArguments() {
    for (const auto& args : argumentSets) {
        for (size_t i = 0; i < args.size(); ++i) {
            if (!validators[i].validate(args[i])) {
                std::cout << "Argument " << args[i] << " is not valid." << std::endl;
            }
        }
        std::cout << "----------" << std::endl;
    }
}
