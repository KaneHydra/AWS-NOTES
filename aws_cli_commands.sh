# 先建立 Root Access Key
# aws configure
# 輸入 root access key 跟 secret


# 建立 user group

aws iam list-users
aws iam list-groups
aws iam list-access-keys

# 新增群組
aws iam create-group --group-name ai0125class
aws iam create-group --group-name ai0125classVPCuser
# 新增群組規則
aws iam attach-group-policy --group-name ai0125class --policy-arn 'arn:aws:iam::aws:policy/AmazonS3FullAccess'
aws iam attach-group-policy --group-name ai0125classVPCuser --policy-arn 'arn:aws:iam::aws:policy/AmazonVPCFullAccess'

# 新增使用者
aws iam create-login-profile --user-name ai0125AdminUser --region us-east-1 --password "Asd21609+"
--tags 'Key=Name,Value=ai0125AdminUser Key=UseCase,Value=Administration'
aws iam create-login-profile --user-name ai0125SuperUser --region us-east-1 --password "Asd21609+"
--tags 'Key=Name,Value=ai0125SuperUser Key=UseCase,Value=RootAccess'
aws iam create-user --user-name ai0125User --region us-east-1
--tags 'Key=Name,Value=ai0125User Key=UseCase,Value=CommonUser'
# 使用者新增規則
aws iam attach-user-policy --user-name ai0125SuperUser --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 把使用者加入群組
aws iam add-user-to-group --user-name ai0125AdminUser --group-name ai0125class
aws iam add-user-to-group --user-name ai0125user --group-name ai0125classVPCuser

# 檢查使用者的 policies
aws iam list-attached-user-policies --user-name ai0125SuperUser

# 查看使用者的 Tags
aws iam list-user-tags --user-name ai0125user
aws iam list-user-tags --user-name ai0125AdminUser
aws iam list-user-tags --user-name ai0125SuperUser


# 新增使用者的 access key
# aws iam create-access-key --user-name <IAM_username>
aws iam create-access-key --user-name ai0125AdminUser

# 移除使用者的 access key
aws iam update-access-key --access-key-id `<Access_Key_ID>` --status Inactive --user-name `<IAM_username>`
aws iam delete-access-key --access-key-id `<Access_Key_ID>` --user-name `<IAM_username>`

aws iam update-access-key --access-key-id AKIATCKAOFSRL7V5QX2S --status Inactive --user-name ai0125AdminUser
aws iam delete-access-key --access-key-id AKIATCKAOFSRL7V5QX2S --user-name ai0125AdminUser

# 建立s3bucket
# bucket name 不能跟別人的重複
aws s3api create-bucket --bucket ai0125s3bucket --region us-east-1
aws s3api create-bucket --bucket ai0125s3bucket2 --region us-east-1
aws s3api put-bucket-tagging --bucket ai0125s3bucket2 --tagging 'TagSet=[{"Key":"Name","Value":"ai0125s3bucket2"},{"Key":"UseCase","Value":"Web Hosting"}]'
aws s3api put-bucket-tagging --bucket ai0125s3bucket2 --tagging "Key:Name,Value:ai0125s3bucket2 Key:UseCase,Value:WebHosting"


# 上傳檔案
aws s3 cp `</path/to/source_file>` s3://ai0125s3bucket/
# 上傳資料夾
aws s3 cp `</path/to/source_folder>` s3://ai0125s3bucket/ --recursive

# 開啓公共訪問權限
aws s3api put-public-access-block --bucket ai0125s3bucket2 --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
# 修改 polocies
aws s3api put-bucket-policy --bucket ai0125s3bucket --policy `<file://path/to/your/local-policy.json>`
aws s3api put-bucket-policy --bucket ai0125s3bucket2 --policy file://./ai0125/BucKetPolicy.json
# 開啓版本控制
aws s3api put-bucket-versioning --bucket ai0125s3bucket --versioning-configuration Status=Enabled
aws s3api put-bucket-versioning --bucket ai0125s3bucket2 --versioning-configuration Status=Enabled

# 從群組移除使用者
aws iam remove-user-from-group --user-name `<User_name>` --group-name `<Group_name>`
aws iam remove-user-from-group --user-name ai0125AdminUser --group-name ai0125class
aws iam remove-user-from-group --user-name ai0125user --group-name ai0125classVPSuser

# 移除使用者
aws iam delete-user --user-name `<IAM_username>`
aws iam delete-user --user-name ai0125user
aws iam delete-user --user-name ai0125AdminUser
aws iam delete-user --user-name ai0125SuperUser


# 移除群組原則
aws iam delete-group-policy --group-name `<group_name>` --policy-name `<policy_name>`
aws iam delete-group-policy --group-name ai0125class --policy-name 'arn:aws:iam::aws:policy/AmazonS3FullAccess'
aws iam delete-group-policy --group-name ai0125classVPCluser --policy-name 'arn:aws:iam::aws:policy/AmazonVPCFullAccess'
# An error occurred (ValidationError) when calling the DeleteGroupPolicy operation: The specified value for policyName is invalid. It must contain only alphanumeric characters and/or the following: +=,.@_-

# 移除群組
aws iam delete-group ai0125class
aws iam delete-group ai0125classVPCuser
# 清空 S3 bucket
aws s3api delete-objects --bucket ai0125s3bucket --delete "$(aws s3api list-object-versions --bucket ai0125s3bucket --output json --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"
# 移除 S3 bucket
aws s3api delete-bucket --bucket ai0125s3bucket

# 設定s3 bucket lifecycle
aws s3api put-bucket-lifecycle-configuration --bucket ai0125s3bucket --lifecycle-configuration `<file://lifecycle.json>`


# 建立資料夾
aws s3api put-object --bucket `<bucket_name>` --key `<new_folder_name>`/ --content-length 0
aws s3api put-object --bucket ai0125s3bucket2 --key ai0125s3folder02/ --content-length 0
# 上傳檔案到s3資料夾
aws s3 cp `/path/to/local/folder` s3://your-bucket-name/folder-name/ --recursive
aws s3 cp ./ai0125/ai0125s3bucket02/ s3://ai0125s3bucket2/ai0125s3folder02/ --recursive
# 移動檔案
aws s3 mv s3://your-bucket-name/source-folder/ s3://your-bucket-name/ --recursive
# 移動單一檔案
aws s3 mv s3://ai0125s3bucket2/ai0125s3folder02/filename.ext s3://ai0125s3bucket2/
# 移動資料夾內的所有檔案
aws s3 mv s3://ai0125s3bucket2/ai0125s3folder02/ s3://ai0125s3bucket2/ --recursive


