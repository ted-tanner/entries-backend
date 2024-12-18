set -a; source .env; set +a

PROJECT_DIR=$(dirname $BASH_SOURCE)
PROJECT_FILES=$(echo $(find $PROJECT_DIR/entries-* -name "*.toml") $(find $PROJECT_DIR/entries-*/src -name "*.rs") $(find $PROJECT_DIR/entries-common/migrations/00000000000001_init -name "*.sql") $(find $PROJECT_DIR/protobuf -name "*.proto") $PROJECT_DIR/entries-server/sample.env $PROJECT_DIR/Readme.md)

emacs $PROJECT_FILES
