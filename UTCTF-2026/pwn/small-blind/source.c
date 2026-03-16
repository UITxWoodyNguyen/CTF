#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char name[256];
    int your_chips = 500;
    int dealer_chips = 500;

    puts("Enter your name:");
    fgets(name, sizeof(name), stdin);

    // Vulnerability: uncontrolled format string
    printf("Welcome to the table, ");
    printf(name);                  // <-- format string vulnerability
    printf("!\n");

    while (1) {
        printf("Your chips: %d | Dealer chips: %d\n", your_chips, dealer_chips);
        printf("Play a hand? (y to play / n to exit): ");

        char cmd[16];
        if (!fgets(cmd, sizeof(cmd), stdin)) break;

        if (cmd[0] == 'n') {
            // Inferred win gate from behavior
            if (your_chips > 1000) {
                puts("utflag{...}");
            } else {
                puts("Better luck next time.");
            }
            break;
        }

        // Poker hand engine here
        // ... complex game logic omitted in real service
    }

    return 0;
}