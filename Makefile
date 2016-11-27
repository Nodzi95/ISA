CC = g++
CFLAGS =  -pedantic
NAME = appdetector
RM = rm -f -v
OBJECTS = appdetector.o

all: $(NAME)

$(NAME) : $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

clean:
	$(RM) *.o $(NAME) 
