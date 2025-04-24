package config

import (
	"log"

	"github.com/spf13/viper"
)

type Env struct {
	AccessTokenSecretKey  string `mapstructure:"ACCESS_TOKEN_SECRET_KEY"`
	RefreshTokenSecretKey string `mapstructure:"REFRESH_TOKEN_SECRET_KEY"`
	AccessTokenExpiresIn  int    `mapstructure:"ACCESS_TOKEN_EXPIRES_IN"`
	RefreshTokenExpiresIn int    `mapstructure:"REFRESH_TOKEN_EXPIRES_IN"`
	Host                  string `mapstructure:"HOST"`
	User                  string `mapstructure:"USER"`
	Password              string `mapstructure:"PASSWORD"`
	Dbname                string `mapstructure:"DBNAME"`
	Port                  string `mapstructure:"PORT"`
	Sslmode               string `mapstructure:"SSLMODE"`
}

func NewEnv() *Env {
	env := Env{}
	viper.SetConfigFile(".env")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("Can't find the file .env : ", err)
	}

	err = viper.Unmarshal(&env)
	if err != nil {
		log.Fatal("Environment can't be loaded: ", err)
	}

	if env.Host == "" || env.Port == "" || env.Dbname == "" || env.User == "" || env.Password == "" || env.AccessTokenSecretKey == "" || env.RefreshTokenSecretKey == "" {
		panic("Veillez à remplir tous les champs dans le fichier .env !")
	}

	return &env
}
