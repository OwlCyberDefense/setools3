
MAKE 		= make
CC		= gcc
LIBAPOL		= ../../../lib/libapol.a
LIBS		= -lm -lfl
OBJS		= test.o $(LIBAPOL)
INCLUDES	= -I../../
CFLAGS		= -Wall -g $(INCLUDES)

all:	partial_load transitive_flow obj_perms perm_map_reload template reload

%.o:	%.c
	$(CC) $(CFLAGS) -c $<

partial_load: $(OBJS) partial_policy_loading.o
	$(CC) partial_policy_loading.o $(CFLAGS) $(OBJS) $(LIBS) -o partial_load

transitive_flow: $(OBJS) transitive_flow.o
	$(CC) transitive_flow.o $(CFLAGS) $(OBJS) $(LIBS) -o transitive_flow

obj_perms: $(OBJS) obj_perms.o
	$(CC) obj_perms.o $(CFLAGS) $(OBJS) $(LIBS) -o obj_perms

perm_map_reload: $(OBJS) perm_map_reload.o
	$(CC) perm_map_reload.o $(CFLAGS) $(OBJS) $(LIBS) -o perm_map_reload

reload: $(OBJS) reload.o
	$(CC) reload.o $(CFLAGS) $(OBJS) $(LIBS) -o reload

template: $(OBJS) template.o
	$(CC) template.o $(CFLAGS) $(OBJS) $(LIBS) -o template

$(LIBAPOL): 
	cd ../../ ; $(MAKE) libapol

clean:
	rm -f partial_load
	rm -f transitive_flow
	rm -f template
	rm -f perm_map_reload
	rm -f obj_perms
	rm -f *.o *~ core core.* a.out

bare:
	rm -f partial_load
	rm -f transitive_flow
	rm -f template
	rm -f perm_map_reload
	rm -f obj_perms
	rm -f *.o *~ core core.* a.out
