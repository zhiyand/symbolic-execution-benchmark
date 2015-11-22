#include <stdio.h>
#include <stdlib.h>

int authenticate(int uid)
{
    if(uid == 1)
        return 1;
    return 0;
}

void admin_code()
{
    printf("Admin code executed!\n");
}

int main(int argc, char ** argv)
{
    int uid = atoi(argv[1]);
    
    // back-door: uid = 2
    if(uid == 2 || authenticate(uid))
    {
        admin_code();
    }
    else{
        printf("Nothing scary happened\n");
    }


    return 0;
}
