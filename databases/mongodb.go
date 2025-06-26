package databases

import (
	"context"
	"net/http"
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

func MongodbAdapter(uri, dbName, collectionName string) (*MongoAdapter, error) {
	clientOpts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, err
	}
	collection := client.Database(dbName).Collection(collectionName)
	return &MongoAdapter{Collection: collection}, nil
}

type User struct {
	Username      string `json:"username" bson:"username"`
	Password      string `json:"password" bson:"password"`
	StudentRole   bool   `json:"studentRole" bson:"student_role"`
	ProfessorRole bool   `json:"professorRole" bson:"professor_role"`
}

func (m *MongoAdapter) CheckAndInsert(user User, w http.ResponseWriter) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	user.Password = string(hashedPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	count, err := m.Collection.CountDocuments(ctx, bson.M{"username": user.Username})
	if err != nil || count > 0 {
		return err
	}
	_, err = m.Collection.InsertOne(ctx, user)
	if err != nil {
		panic(err)
	}
	return nil
}

type ClaimedUser struct {
	Username string `json:"username" bson:"username"`
	Password string `json:"password" bson:"password"`
}
type ClaimedDatabase struct {
	Username string
	Id       interface{}
	Role     []string
	Password string
}

func (m *MongoAdapter) CheckLogin(claimedUser ClaimedUser, w http.ResponseWriter) (error, *ClaimedDatabase) {
	var result struct {
		ID       primitive.ObjectID `bson:"_id"`
		Username string             `bson:"username"`
		Password string             `bson:"password"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := m.Collection.FindOne(ctx, bson.M{"username": claimedUser.Username}).Decode(&result)
	if err != nil {
		return err, &ClaimedDatabase{}
	}
	claimedDatabase := &ClaimedDatabase{
		Username: result.Username,
		Password: result.Password,
		Id:       result.ID,
	}

	return nil, claimedDatabase

}
func (m *MongoAdapter) GetRoleLogin(claimedDatabase *ClaimedDatabase, w http.ResponseWriter) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cursor, err := m.Collection.Find(ctx, bson.M{"user_id": claimedDatabase.Id})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	var roleSlice []string
	for cursor.Next(ctx) {
		var roleDoc struct {
			roleId int `bson:"role_id"`
		}
		err = cursor.Decode(&roleDoc.roleId)
		if err != nil {
			http.Error(w, "not allowed yet", http.StatusForbidden)
			return err
		}
		roleSlice = append(roleSlice, strconv.Itoa(roleDoc.roleId))
	}
	claimedDatabase.Role = roleSlice
	return nil

}
