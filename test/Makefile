
LIBAPOL		= ../lib/libapol.a
OBJS		= test.o $(LIBAPOL)
INCLUDES	= -I../libapol/
CFLAGS		+= $(INCLUDES)

all:	partial_load transitive_flow obj_perms perm_map_reload template reload subtract

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

subtract: $(OBJS) subtract.o
	$(CC) subtract.o $(CFLAGS) $(OBJS) $(LIBS) -o subtract

template: $(OBJS) template.o
	$(CC) template.o $(CFLAGS) $(OBJS) $(LIBS) -o template

$(LIBAPOL): 
	cd .. ; $(MAKE) libapol

clean:
	rm -f partial_load transitive_flow template reload perm_map_reload obj_perms subtract *.o

bare: clean
	rm -f *~ core core.* a.out
