#include <stdio.h>
#include <stdlib.h>

int func1(int x);
int func2(int x);
int func3(int x);
int func4(int x);
int func5(int x);
int func6(int x);
int func7(int x);
int func8(int x);

int func1(int x) {
    if (x > 100) {
        return func2(x + 100);
    } else {
        return func3(x);
    }
}

int func2(int x) {
    if (x <= 499) {
        return func4(x - 86);
    } else {
        return func5(x + 13);
    }
}

int func3(int x) {
    return func7(x);
}

int func4(int x) {
    int tmp = 17;
    tmp = func1(tmp);
    return x;
}

int func5(int x) {
    x = func8(x);
    return x;
}

int func6(int x) {
    int a = x;
    int b = 314;
    int c = 1932;
    int counter = 0;

    while (counter <= 899) {
        int temp = c * 800;
        int q = temp / b;
        int r = temp - (q * b);
        a = r;
        counter++;
    }
    return a;
}

int func7(int x) {
    if (x <= 100) return 7;
    return x;
}

int func8(int x) {
    return x + 2;
}

int main(void) {
    int val = 1151828495;   // <-- fixed input inserted here

    int result = func1(val);

    printf("Result: %ld\n", (long)result);
    return 0;
}
