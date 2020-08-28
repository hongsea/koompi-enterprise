CREATE TABLE userinfo (
    userid bigserial PRIMARY KEY ,
    usernamelogin TEXT NOT NULL ,
    firstname TEXT NOT NULL ,
    surname TEXT NOT NULL ,
    profilepath TEXT NOT NULL ,
    scriptpath TEXT NOT NULL ,
    homedirectory TEXT NOT NULL ,
    homedrive TEXT NOT NULL ,
    unixhome TEXT NOT NULL ,
    jobtitle TEXT NOT NULL ,
    mailaddress TEXT NOT NULL ,
    description TEXT NOT NULL )


--    Example:
--   insert into userinfo (usernamelogin,firstname,surname,profilepath,scriptpath,homedirectory,homedrive,unixhome,jobtitle,mailaddress,description)VALUES ('hongsea','Heng','Hongsea','/home/samba/home/hongsea','logon.bat','/home/LOVEKOOMPI/hongsea','G','/home/LOVEKOOMPI/hongsea','Network','hongsea@gmail.com','For IT Network')

-- create store PROCEDURE
CREATE OR REPLACE PROCEDURE insert_userinfo (user_login TEXT ,user_firstname TEXT ,user_surname TEXT ,user_profilepath TEXT ,user_scriptpath TEXT ,user_homedirectory TEXT ,user_homedrive TEXT ,user_unixhome TEXT ,user_jobtitle TEXT ,user_mailaddress TEXT ,user_description TEXT )
LANGUAGE plpgsql
AS $$
BEGIN
    insert into userinfo (usernamelogin,firstname,surname,profilepath,scriptpath,homedirectory,homedrive,unixhome,jobtitle,mailaddress,description)VALUES (user_login,user_firstname,user_surname,user_profilepath,user_scriptpath,user_homedirectory,user_homedrive,user_unixhome,user_jobtitle,user_mailaddress,user_description);
END
$$
