export DATABASE_URL="postgres://budgetappdbuser:0Psrku4jzIRi5mD0ctOB@localhost/budgetapp_test"

PROJECT_DIR=$(dirname $BASH_SOURCE)
emacs $PROJECT_DIR/budgetapp-*/*.toml $PROJECT_DIR/budgetapp-*/**/*.toml $PROJECT_DIR/budgetapp-utils/migrations/**/*.sql $PROJECT_DIR/budgetapp-*/*.rs $PROJECT_DIR/budgetapp-*/**/*.rs $PROJECT_DIR/Readme.md
