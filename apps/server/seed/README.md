Seed files (configs.json, providers.json) consumed by the Go entrypoint
on first boot.

For the MVP these are not yet wired — copy them from the legacy backend
(apps/server/prisma/) when porting the seed step:

    cp ../server/prisma/configs.json   .
    cp ../server/prisma/providers.json .

The Go binary will then read them from /seed/ inside the image and
install them into /data/prisma/ if missing.
