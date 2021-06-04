#include <iostream>

template<typename T, size_t N>
void someFunction(T (&array)[N]) {
    std::cout << "Executing some function" << std::endl;
    std::cout << "The array size is: " << N << std::endl;

    if (N < 5)
        throw std::runtime_error("Array too small.");

    for(int i = 0; i < 5; i++) {
        array[i] = 'a';
    }

    std::cout << "Array: " << array << std::endl;
    return;
}
 
int main() {
    char *someArray = NULL;
    char *anotherArray = NULL;
    bool someErrorCondition = true;

    std::cout << "This is a dynamic memory test." << std::endl;

    someArray = new (std::nothrow) char[5];
    if(!someArray) {
        std::cout << "Bad memory allocation." << std::endl;
    }

    anotherArray = new (std::nothrow) char[6];
    if(!anotherArray) {
        std::cout << "Bad memory allocation." << std::endl;
    }

    try {
        std::cout << "Testing some function with stack arrays." << std::endl;

        std::cout << "Bigger array." << std::endl;
        char array[6];
        someFunction(array);

        std::cout << "Array out of scope: " << array << std::endl;

        if(someErrorCondition)
            throw std::runtime_error("Some error condition has been triggered.");
    } catch(const std::exception& e) {
        std::cout << "Trying to delete arrays." << std::endl;
        delete[] someArray;
        delete[] anotherArray;
        std::cerr << e.what() << '\n';
        return 0;
    }

    std::cout << "Executing code after try/catch." << std::endl;
    delete[] someArray;
    delete[] anotherArray; 
    return 0;
}

/*
int main() {
    char *someArray = NULL;
    char *anotherArray = NULL;
    bool someErrorCondition = true;

    try {
        std::cout << "This is a dynamic memory test." << std::endl;

        someArray = new char[5];
        std::cout << "Some array has been initialized." << std::endl;

        if(someErrorCondition)
            throw std::runtime_error("Some error condition has been triggered.");

        std::cout << "Executing code after some error condition." << std:: endl;
        anotherArray = new char[5];
    } catch(const std::exception& e) {
        std::cout << "Trying to delete arrays." << std::endl;
        delete[] someArray;
        delete[] anotherArray; //undefined behaviour
        std::cerr << e.what() << '\n';
        return 0;
    }

    std::cout << "Executing code after try/catch." << std::endl;
    delete[] someArray;
    delete[] anotherArray; 
    return 0;
}

*/