pub struct VerifyUserExpiredLinkPage {}
pub struct VerifyUserLinkMissingTokenPage {}
pub struct VerifyUserInvalidLinkPage {}
pub struct VerifyUserAccountNotFoundPage {}
pub struct VerifyUserInternalErrorPage {}
pub struct VerifyUserSuccessPage {}

pub struct DeleteUserExpiredLinkPage {}
pub struct DeleteUserLinkMissingTokenPage {}
pub struct DeleteUserInvalidLinkPage {}
pub struct DeleteUserAlreadyScheduledPage {}
pub struct DeleteUserAccountNotFoundPage {}
pub struct DeleteUserInternalErrorPage {}
pub struct DeleteUserSuccessPage {}

impl VerifyUserExpiredLinkPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Verification</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>This link has expired. You will need to recreate your account to obtain a new \
             link.</h1>

             <script>
               const urlQueries = new URLSearchParams(window.location.search);
               const token = urlQueries.get('UserCreationToken');

               if (token !== null) {
                 const decoded_token = atob(token);
                 const claims = JSON.parse(decoded_token);

                 if (claims['exp'] !== null) {
                   const hourAfterExpiration = claims['exp'] + 3600;
                   const accountAvailableForRecreate = new Date(hourAfterExpiration * 1000);
                   const now = new Date();

                   if (accountAvailableForRecreate > now) {
                     let recreateMessage = document.createElement('h3');

                     const millisUntilCanRecreate = Math.abs(now - accountAvailableForRecreate);
                     const minsUntilCanRecreate = Math.ceil((millisUntilCanRecreate / 1000) / 60);

                     const timeString = minsUntilCanRecreate > 1
                       ? minsUntilCanRecreate + ' minutes.'
                       : '1 minute.'

                     recreateMessage.innerHTML = 'You can recreate your account in ' + timeString;

                     document.body.appendChild(recreateMessage);
                   }
                 }
               }
             </script>
           </body>
         </html>"
    }
}

impl VerifyUserLinkMissingTokenPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Verification</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>This link is invalid because it is missing a token.</h1>
           </body>
         </html>"
    }
}

impl VerifyUserInvalidLinkPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Verification</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>This link is invalid.</h1>
           </body>
         </html>"
    }
}

impl VerifyUserAccountNotFoundPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Verification</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>Could not find the correct account. This is probably an error on our \
             part.</h1>
             <h3>We apologize. We'll try to fix this. Please try again in a few hours.</h3>
           </body>
         </html>"
    }
}

impl VerifyUserInternalErrorPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Verification</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>Could not verify account due to an error.</h1>
             <h3>We're sorry. We'll try to fix this. Please try again in a few hours.</h3>
           </body>
         </html>"
    }
}

impl VerifyUserSuccessPage {
    pub fn generate(user_email: &str) -> String {
        format!(
            "<!DOCTYPE html>
             <html>
               <head>
                 <title>Entries App User Verification</title>
                 <style>
                   body {{
                     font-family: Arial, sans-serif;
                   }}
                 </style>
               </head>
               <body>
                 <h1>User verified</h1>
                 <h3>User email address: {}</h3>
                 <h2>You can now sign into the app using your email address and password.</h2>
               </body>
             </html>",
            user_email,
        )
    }
}

impl DeleteUserExpiredLinkPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Deletion</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>This link has expired. You will need initiate the deletion process again.</h1>

             <script>
               const urlQueries = new URLSearchParams(window.location.search);
               const token = urlQueries.get('UserDeletionToken');

               if (token !== null) {
                 const decoded_token = atob(token);
                 const claims = JSON.parse(decoded_token);

                 if (claims['exp'] !== null) {
                   const hourAfterExpiration = claims['exp'] + 3600;
                   const accountAvailableForDelete = new Date(hourAfterExpiration * 1000);
                   const now = new Date();

                   if (accountAvailableForDelete > now) {
                     let deleteMessage = document.createElement('h3');

                     const millisUntilCanDelete = Math.abs(now - accountAvailableForDelete);
                     const minsUntilCanDelete = Math.ceil((millisUntilCanDelete / 1000) / 60);

                     const timeString = minsUntilCanDelete > 1
                     ? minsUntilCanDelete + ' minutes.'
                     : '1 minute.'

                     deleteMessage.innerHTML = 'You can re-initate deletion of your account in '
                     + timeString;

                     document.body.appendChild(deleteMessage);
                   }
                 }
               }
             </script>
           </body>
         </html>"
    }
}

impl DeleteUserLinkMissingTokenPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Deletion</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>This link is invalid because it is missing a token.</h1>
           </body>
         </html>"
    }
}

impl DeleteUserInvalidLinkPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Deletion</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>This link is invalid.</h1>
           </body>
         </html>"
    }
}

impl DeleteUserAlreadyScheduledPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App Account Deletion</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>Account is already scheduled to be deleted.</h1>
           </body>
         </html>"
    }
}

impl DeleteUserAccountNotFoundPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App User Deletion</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>Could not find the correct account. This is probably an error on our \
             part.</h1>
             <h3>We apologize. We'll try to fix this. Please try again in a few hours.</h3>
           </body>
         </html>"
    }
}

impl DeleteUserInternalErrorPage {
    pub fn generate() -> &'static str {
        "<!DOCTYPE html>
         <html>
           <head>
             <title>Entries App Account Deletion</title>
             <style>
               body {
                 font-family: Arial, sans-serif;
               }
             </style>
           </head>
           <body>
             <h1>Could not verify account deletion due to an error.</h1>
             <h2>We're sorry. We'll try to fix this. Please try again in a few hours.</h2>
           </body>
         </html>"
    }
}

impl DeleteUserSuccessPage {
    pub fn generate(user_email: &str, days_until_deletion: u64) -> String {
        format!(
            "<!DOCTYPE html>
             <html>
               <head>
                 <title>Entries App Account Deletion</title>
                 <style>
                   body {{
                     font-family: Arial, sans-serif;
                   }}
                 </style>
               </head>
               <body>
                 <h1>Your account has been scheduled for deletion.</h1>
                 <h2>User email address: {}</h2>
                 <h2>Your account will be deleted in about {} days. You can cancel your \
                 account deletion from the app.</h2>
               </body>
             </html>",
            user_email, days_until_deletion,
        )
    }
}
