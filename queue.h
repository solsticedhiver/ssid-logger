#ifndef SIMPLE_QUEUE
#define SIMPLE_QUEUE

struct Node {
  void *value;
  struct Node *next;
};

typedef struct Queue {
  int size;
  int max_size;
  struct Node *head;
  struct Node *tail;
} queue_t;

extern queue_t *new_queue(int capacity);

extern int enqueue(queue_t * q, void *value);

extern void *dequeue(queue_t * q);

extern void free_queue(queue_t * q);

#endif
