import os
from flask_migrate import Manager, Migrate, MigrateCommand

from app import app, db


migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()
