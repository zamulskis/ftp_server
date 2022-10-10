LIBS = -lssl -lcrypto
CFLAGS = -Wall -Werror -g  -ggdb3 -pipe -I include
src = $(wildcard src/*.c)
headers = $(wildcard include/*.h)
obj = $(patsubst src/%.c, build/%.o, $(src))
BUILDDIR = build


app: $(obj)
	$(CC) $(CFLAGS) $(obj) -o app $(LIBS)
	

build/%.o: src/%.c ${headers}
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)  -c $< -o $@ 


clean:
	rm build/*.o app
