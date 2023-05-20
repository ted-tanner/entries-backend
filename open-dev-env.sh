export DATABASE_URL="postgres://entriesdbuser:0Psrku4jzIRi5mD0ctOB@localhost/entries_test"

PROJECT_DIR=$(dirname $BASH_SOURCE)
PROJECT_FILES=$(echo $(find $PROJECT_DIR/entries-* -name "*.toml") $(find $PROJECT_DIR/entries-*/src -name "*.rs") $(find $PROJECT_DIR/entries-utils/migrations/00000000000001_init -name "*.sql") $PROJECT_DIR/Readme.md)

emacs $PROJECT_FILES
