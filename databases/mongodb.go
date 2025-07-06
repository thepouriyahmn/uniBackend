package databases

import (
	"context"
	"errors"
	"fmt"

	"strconv"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type MongoAdapter struct {
	Collection *mongo.Collection
}

type User struct {
	Username      string `json:"username" bson:"username"`
	Password      string `json:"password" bson:"password"`
	StudentRole   bool   `json:"studentRole" bson:"student_role"`
	ProfessorRole bool   `json:"professorRole" bson:"professor_role"`
}

//	type ClaimedUser struct {
//		Username string `json:"username" bson:"username"`
//		Password string `json:"password" bson:"password"`
//	}
type ClaimedDatabase struct {
	Username string
	Id       interface{}
	Role     []string
	Password string
}

func (m Mongodbadapter) CheckUserByUsernameAndPassword(username, password string) (interface{}, error) {
	type Result struct {
		ID            primitive.ObjectID `bson:"_id"`
		Username      string             `bson:"username"`
		Password      string             `bson:"password"`
		StudentRole   bool               `bson:"student_role"`
		ProfessorRole bool               `bson:"professor_role"`
	}
	var res Result

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// var raw bson.M
	// err := m.db.Collection("users").FindOne(ctx, bson.M{"username": username}).Decode(&raw)
	// fmt.Printf("ID TYPE: %T\n", raw["_id"])

	// if err != nil {
	// 	fmt.Println("err: ", err)
	// }
	// fmt.Printf("RAW DATA: %+v\n", raw)

	err := m.db.Collection("users").FindOne(ctx, bson.M{"username": username}).Decode(&res)

	if err != nil {
		fmt.Println("ERROR IS: ", err)
		return "", errors.New("user not found")
	}
	err = bcrypt.CompareHashAndPassword([]byte(res.Password), []byte(password))

	if err != nil {
		fmt.Println("wrong")
		return "", errors.New("password not valid")

	}
	fmt.Println("right")

	// claimedDatabase := &ClaimedDatabase{
	// 	Username: result.Username,
	// 	Password: result.Password,
	// 	Id:       result.ID,
	// }
	fmt.Println("id sent: ", res.ID)
	return res.ID, nil

}
func (m Mongodbadapter) GetRoleById(id interface{}) ([]string, error) {

	oid, ok := id.(primitive.ObjectID)
	fmt.Println("oid is : ", oid)
	if !ok {
		return []string{}, fmt.Errorf("id is not of type primitive.ObjectID, got: %T", id)
	}
	var roleSlice []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fmt.Println("id: ", id)
	cursor, err := m.db.Collection("user_roles").Find(ctx, bson.M{"user_id": oid})
	if err != nil {
		fmt.Println("error is: ", err)
		return []string{}, errors.New("user not found")
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var roleDoc struct {
			ID      primitive.ObjectID `bson:"_id"`
			user_id primitive.ObjectID `bson:"user_id"`
			roleId  int                `bson:"role_id"`
		}
		err = cursor.Decode(&roleDoc)
		fmt.Println("roledoc is: ", roleDoc)
		if err != nil {
			fmt.Println("error is: ", err)
			return []string{}, err
		}
		roleSlice = append(roleSlice, strconv.Itoa(roleDoc.roleId))
	}

	return roleSlice, nil

}

// ////////////////////
type Mongodbadapter struct {
	db *mongo.Database
}

func NewMongodbAdapter(uri, dbName string) (Mongodbadapter, error) {
	clientOpts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return Mongodbadapter{}, err
	}
	db := client.Database(dbName) //.Collection("users")
	return Mongodbadapter{db: db}, nil
}
func (m Mongodbadapter) CheckUserByName(username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	count, err := m.db.Collection("users").CountDocuments(ctx, bson.M{"username": username})
	fmt.Println("is: ", count)
	if err != nil || count > 0 {
		fmt.Println("error has returned")

		return errors.New("name has been picked before")
	}
	return nil
}
func (m Mongodbadapter) InsertUser(user User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	user.Password = string(hashedPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err != nil {
		panic(err)
	}
	_, err = m.db.Collection("users").InsertOne(ctx, user)
	if err != nil {
		panic(err)
	}
	return nil
}
