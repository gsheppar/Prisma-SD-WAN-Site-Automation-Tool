db.createUser(
        {
            user: "flaskuser",
            pwd: "PrismaSDWAN",
            roles: [
                {
                    role: "readWrite",
                    db: "flaskdb"
                }
            ]
        }
);