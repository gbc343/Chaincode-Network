'use strict'
const path=require('path')
const gateway=require("./appGateway")
const {userId}=require("./connections/org1-config.json")

async function main(){
    console.log("####### Fabric sample application #######")
    console.log(`####### userId: ${userId} #######`)
    const customer = {
       id: "customer19",
       firstName: "Harry",
       lastName: "Kerrington",
       transitId: "TTC"
    }
   
   const enrolledCustomer = await gateway.EnrollCustomer(userId, customer.id, customer.firstName, customer.lastName, customer.transitId)
   console.log(`####### Enrolled Customer: ${JSON.stringify(enrolledCustomer)} #######`)


   const returnedCutomer = await gateway.GetCustomer(userId, customer.id)
   console.log(`####### Get Customer: ${JSON.stringify(returnedCutomer)} #######`)

}

main()