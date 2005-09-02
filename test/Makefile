MAKE 		= make
CC		= gcc
LIBAPOL		= ../libapol/libapol.a
LIBS		= -lm -lfl $(LIBSELINUX)
OBJS		= test.o $(LIBAPOL)
INCLUDES	= -I../libapol/
CFLAGS		+= $(INCLUDES)

TESTS		= partial_policy_loading transitive_flow obj_perms perm_map_reload template reload roles binpol relabel role_rules subtract source_load
DATE 		:= $(shell date +%Y%m%d%H%M)

all : $(TESTS)
	

run : $(foreach test,$(TESTS),$(test).res)
	cat $^ > results/tests-$(DATE).results

%.res : %.o $(OBJS)
	@echo $* > $*.res0
	-@./$* > $*.res1 2> $*.res2 
	@cat $*.res0 $*.res1 $*.res2 > $@ 
	@rm -f $*.res[012]

% : %.o $(OBJS) $(LIBAPOL) 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

test.o : test.c test.h
	$(CC) $(CFLAGS) -c $<

%.o : %.c
	$(CC) $(CFLAGS) -c $<

$(LIBAPOL): libapol

libapol: 
	$(MAKE) -C .. libapol

partial_policy_loading : partial_policy_loading.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

transitive_flow : transitive_flow.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

obj_perms : obj_perms.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

perm_map_reload : perm_map_reload.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

template : template.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

reload : reload.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

roles : roles.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

binpol : binpol.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

relabel : relabel.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

role_rules : role_rules.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

subtract : subtract.o $(OBJS) libapol 
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

source_load: source_load.o $(OBJS) $(LIBAPOL)
	$(CC) $< $(CFLAGS) $(OBJS) $(LIBS) -o $@

.PHONY : clean bare libapol

clean : 
	rm -f *.o *.res $(TESTS) ./results/tests-*.results

bare : clean
	rm -f *~ core core.* a.out
