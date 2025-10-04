#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

// Simple target program for debugging
volatile int counter = 0;

void* worker_thread(void* arg) {
    int id = *(int*)arg;
    printf("[Thread %d] Started\n", id);

    while (1) {
        counter++;
        printf("[Thread %d] Counter: %d\n", id, counter);
        sleep(2);
    }

    return NULL;
}

int main() {
    printf("[Target] PID: %d\n", getpid());
    printf("[Target] Starting worker threads...\n");

    pthread_t thread1, thread2;
    int id1 = 1, id2 = 2;

    pthread_create(&thread1, NULL, worker_thread, &id1);
    pthread_create(&thread2, NULL, worker_thread, &id2);

    // Main thread work
    while (1) {
        printf("[Main] Counter: %d\n", counter);
        sleep(3);
    }

    return 0;
}
