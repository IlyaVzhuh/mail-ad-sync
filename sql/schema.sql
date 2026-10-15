-- Extra tables in the Postfix Admin database (`postfix`, MariaDB) used by ad-mail-sync,
-- mail-lastseen and mail-inactivity. Postfix Admin's own tables are not changed.

CREATE TABLE ad_user (            -- AD user <-> mailbox link, keyed by objectGUID (survives renames)
  object_guid  CHAR(36)      NOT NULL PRIMARY KEY,
  sam          VARCHAR(64)   NOT NULL,
  username     VARCHAR(255)  NOT NULL,       -- mailbox.username
  dn           VARCHAR(1024) NOT NULL,
  enabled      TINYINT(1)    NOT NULL,
  first_seen   DATETIME      NOT NULL,
  synced_at    DATETIME      NOT NULL,
  UNIQUE KEY (username),
  KEY (sam)
);

CREATE TABLE mailbox_block (      -- login refused by Dovecot; delivery keeps working
  username  VARCHAR(255) NOT NULL PRIMARY KEY,
  reason    VARCHAR(32)  NOT NULL,           -- ad_disabled | manual
  since     DATETIME     NOT NULL,
  note      VARCHAR(255) NULL
);

CREATE TABLE ad_sync_state (      -- first_run, last_ad_count, last_run, last_mode
  k  VARCHAR(64)  NOT NULL PRIMARY KEY,
  v  VARCHAR(255) NOT NULL
);

CREATE TABLE mailbox_action_log (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  at        DATETIME     NOT NULL,
  username  VARCHAR(255) NOT NULL,
  action    VARCHAR(32)  NOT NULL,           -- link | unlink | create | block | unblock | disable
  reason    VARCHAR(32)  NOT NULL,
  note      VARCHAR(255) NULL,
  KEY (username)
);

CREATE TABLE mailbox_lastseen (   -- newest IMAP/POP/SMTP login per mailbox
  username    VARCHAR(255) NOT NULL PRIMARY KEY,
  last_login  DATETIME     NOT NULL,
  source      VARCHAR(8)   NOT NULL         -- imap | pop3 | smtp
);
