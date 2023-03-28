LD_LIBRARY_PATH=./ ./exe

asan: asan.c
	gcc -s -O0 -fsanitize=address

clean:
	rm -f asan *.o