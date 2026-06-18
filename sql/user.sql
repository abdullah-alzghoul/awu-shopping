
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";
SET NAMES utf8mb4;


CREATE TABLE `user` (
  `id`              int(11)                NOT NULL AUTO_INCREMENT,
  `name`            varchar(100)           NOT NULL,
  `email`           varchar(150)           NOT NULL,
  `password`        varchar(255)           NOT NULL,
  `role`            enum('user','manager') NOT NULL DEFAULT 'user',
  `avatar_shape`    varchar(20)            NOT NULL DEFAULT 'circle',
  `avatar_color`    varchar(10)            NOT NULL DEFAULT '#1f4fff',
  `avatar_letter`   varchar(5)                      DEFAULT NULL,
  `avatar_image`    varchar(255)                    DEFAULT NULL,
  `name_changed_at` datetime                        DEFAULT NULL,
  `session_token`   varchar(64)                     DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

COMMIT;

CREATE TABLE `products` (
  `id`          int(11)        NOT NULL AUTO_INCREMENT,
  `name`        varchar(150)   NOT NULL,
  `description` text           NOT NULL,
  `price`       decimal(10,2)  NOT NULL,
  `image`       varchar(255)   NOT NULL,
  `category`    varchar(100)   DEFAULT NULL,
  `featured`    tinyint(1)     NOT NULL DEFAULT 0,
  `created_at`  datetime       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


INSERT INTO `products` (`name`, `description`, `price`, `image`, `category`, `featured`) VALUES
('Nike Running Shoes',    'Lightweight and breathable running shoes for everyday training.',       89.99,  '1.png',    'Shoes',       1),
('Adidas Sport T-Shirt',  'Moisture-wicking fabric keeps you dry during intense workouts.',        34.99,  '2.webp',   'Clothing',    1),
('Gym Gloves Pro',        'Full-grip gloves with wrist support for heavy lifting.',                19.99,  '3.webp',   'Accessories', 1),
('Resistance Bands Set',  'Set of 5 bands with varying resistance levels for full-body training.', 24.99,  '4.webp',   'Equipment',   1),
('Sport Water Bottle',    'Double-wall insulated bottle keeps water cold for 24 hours.',           14.99,  '5.webp',   'Accessories', 1),
('Running Shorts',        'Lightweight shorts with inner lining and zippered pocket.',             29.99,  '6.webp',   'Clothing',    1),
('Foam Roller',           'High-density foam roller for muscle recovery and deep tissue massage.', 27.99,  '7.webp',   'Recovery',    0),
('Sport Backpack',        'Water-resistant 30L backpack with padded laptop compartment.',          49.99,  '8.png',    'Bags',        0);


CREATE TABLE `bans` (
  `id`        int(11)       NOT NULL AUTO_INCREMENT,
  `ip`        varchar(45)   NOT NULL,
  `reason`    varchar(255)  DEFAULT NULL,
  `banned_at` datetime      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `until`     varchar(50)   DEFAULT NULL,
  `is_active` tinyint(1)    NOT NULL DEFAULT 1,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


CREATE TABLE `password_history` (
  `id`         int(11)      NOT NULL AUTO_INCREMENT,
  `user_id`    int(11)      NOT NULL,
  `password`   varchar(255) NOT NULL,
  `changed_at` datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `fk_ph_user` FOREIGN KEY (`user_id`)
    REFERENCES `user` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;