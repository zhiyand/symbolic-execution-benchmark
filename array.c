/**
 * A very simple array out-of-bound memory error
 */

#include <stdio.h>

int main(int argc, char ** argv)
{
    int iterations = atoi(argv[1]);

    int array[20] = { 0 };

    int i = 0;
    for(i = 0; i < iterations; i++)
    {
        array[i] = 100;
    }

    return 0;
}
