#include "CustomValidator.hpp"

CustomValidator::CustomValidator(const std::string& name, int minLength, int maxLength, int rangeFrom, int rangeTo)
    : argName(name), minLength(minLength), maxLength(maxLength) {} // tutaj obok maxLength(maxLength) trzeba dodac brakujace definicje (bazujesz na zmiennych z linii 3)

bool CustomValidator::validate(const std::string& argument) const {
    // te rozwiazanie nie zadziala
    int argLength = argument.length();
    // powyzsze wywal odkomentuj ponizsze, chodzi o to ze rzutujemy dane na int bez utraty precyzji
    // int argLength = static_cast<int>(argument.length());
    int argValue = std::stoi(argument);

    if (argLength < minLength || argLength > maxLength) {
        std::cout << "Argument " << argName << " must have length between " << minLength << " and " << maxLength << "." << std::endl;
        return false;
    }
    // stworz analogicznego ifa jak powyzej zamieniajac odpowiednio tylko 2 zmienne dla zakresu (rangeFrom, rangeTo)
    // ten zakomentowany kod to zawartosc naszego ifa
        // std::cout << "Argument " << argName << " must be in the range [" << rangeFrom << ", " << rangeTo << "]." << std::endl;
        // return false;

    return true;
}
