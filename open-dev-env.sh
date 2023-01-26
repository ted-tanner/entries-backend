export DATABASE_URL="postgres://budgetappdbuser:0Psrku4jzIRi5mD0ctOB@localhost/budgetapp_test"

PROJECT_DIR=$(dirname $BASH_SOURCE)
PROJECT_FILES=$(echo $(find $PROJECT_DIR/budgetapp-* -name "*.toml") $(find $PROJECT_DIR/budgetapp-*/src -name "*.rs") $(find $PROJECT_DIR/budgetapp-utils/migrations/00000000000001_init -name "*.sql"))

emacs $PROJECT_FILES
