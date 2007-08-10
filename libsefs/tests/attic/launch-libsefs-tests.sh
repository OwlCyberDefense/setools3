# Mount the virtual filesystems, execute the the real test, then
# unmount those filesystems.

mkdir -p non-mls
mkdir -p mls
./fuse_non_mls non-mls
./libsefs-tests
result=$?
fusermount -u non-mls
rmdir non-mls
rmdir mls
exit ${result}
