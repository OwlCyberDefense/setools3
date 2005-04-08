
MAKE 		= make
CC		= gcc
LIBAPOL		= ../libapol/libapol.a
LIBS		= -lm -lfl $(LIBSELINUX)
OBJS		= test.o $(LIBAPOL)
INCLUDES	= -I../libapol/
CFLAGS		+= $(INCLUDES)

all:	partial_load transitive_flow obj_perms perm_map_reload template reload roles binpol relabel role_rules

%.o:	%.c
	$(CC) $(CFLAGS) -c $<

partial_load: $(OBJS) partial_policy_loading.o
	$(CC) partial_policy_loading.o $(CFLAGS) $(OBJS) $(LIBS) -o partial_load

transitive_flow: $(OBJS) transitive_flow.o
	$(CC) transitive_flow.o $(CFLAGS) $(OBJS) $(LIBS) -o transitive_flow
	
binpol: $(OBJS) binpol.o
	$(CC) binpol.o $(CFLAGS) $(OBJS) $(LIBS) -o binpol

obj_perms: $(OBJS) obj_perms.o
	$(CC) obj_perms.o $(CFLAGS) $(OBJS) $(LIBS) -o obj_perms

perm_map_reload: $(OBJS) perm_map_reload.o
	$(CC) perm_map_reload.o $(CFLAGS) $(OBJS) $(LIBS) -o perm_map_reload

reload: $(OBJS) reload.o
	$(CC) reload.o $(CFLAGS) $(OBJS) $(LIBS) -o reload

template: $(OBJS) template.o
	$(CC) template.o $(CFLAGS) $(OBJS) $(LIBS) -o template

roles: $(OBJS) roles.o
	$(CC) roles.o $(CFLAGS) $(OBJS) $(LIBS) -o roles

relabel: $(OBJS) relabel.o $(LIBAPOL)
	$(CC) relabel.o $(CFLAGS) $(OBJS) $(LIBS) $(LIBAPOL) -o relabel

role_rules: $(OBJS) role_rules.o $(LIBAPOL)
	$(CC) role_rules.o $(CFLAGS) $(OBJS) $(LIBS) $(LIBAPOL) -o role_rules

$(LIBAPOL): 
	cd ../ ; $(MAKE) libapol

clean:
	rm -f *.o partial_load transitive_flow template reload perm_map_reload obj_perms binpol roles relabel

bare: clean
	rm -f *~ core core.* a.out
