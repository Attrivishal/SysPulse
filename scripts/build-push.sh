

# AWS ECR and EKS Deployment Script

# Configuration
AWS_REGION="ap-south-1"
ECR_REPO_NAME="flask-app"
CLUSTER_NAME="your-eks-cluster-name"
IMAGE_TAG="latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting EKS Deployment Pipeline${NC}"

# Step 1: Login to AWS ECR
echo -e "${YELLOW}Step 1: Logging into AWS ECR...${NC}"
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $(aws sts get-caller-identity --query 'Account' --output text).dkr.ecr.$AWS_REGION.amazonaws.com

# Step 2: Build Docker image
echo -e "${YELLOW}Step 2: Building Docker image...${NC}"
docker build -t $ECR_REPO_NAME:$IMAGE_TAG .

# Step 3: Tag image for ECR
ECR_REPO=$(aws sts get-caller-identity --query 'Account' --output text).dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME
echo -e "${YELLOW}Step 3: Tagging image for ECR...${NC}"
docker tag $ECR_REPO_NAME:$IMAGE_TAG $ECR_REPO:$IMAGE_TAG

# Step 4: Push to ECR
echo -e "${YELLOW}Step 4: Pushing image to ECR...${NC}"
docker push $ECR_REPO:$IMAGE_TAG

# Step 5: Update k8s deployment with new image
echo -e "${YELLOW}Step 5: Updating Kubernetes deployment...${NC}"
sed -i.bak "s|YOUR_ECR_REPO|$ECR_REPO|g" k8s/manifests/deployment.yaml

# Step 6: Configure kubectl for EKS
echo -e "${YELLOW}Step 6: Configuring kubectl for EKS...${NC}"
aws eks update-kubeconfig --region $AWS_REGION --name $CLUSTER_NAME

# Step 7: Apply Kubernetes manifests
echo -e "${YELLOW}Step 7: Applying Kubernetes manifests...${NC}"
kubectl apply -f k8s/manifests/namespace.yaml
kubectl apply -f k8s/manifests/configmap.yaml
kubectl apply -f k8s/manifests/secret.yaml
kubectl apply -f k8s/manifests/redis.yaml
sleep 10  # Wait for Redis
kubectl apply -f k8s/manifests/deployment.yaml
kubectl apply -f k8s/manifests/service.yaml
kubectl apply -f k8s/manifests/ingress.yaml

# Step 8: Check deployment status
echo -e "${YELLOW}Step 8: Checking deployment status...${NC}"
kubectl get pods -n flask-app
kubectl get svc -n flask-app
kubectl get ingress -n flask-app

echo -e "${GREEN}✅ Deployment completed!${NC}"
echo -e "${GREEN}📋 To get the ALB URL:${NC}"
echo "kubectl get ingress -n flask-app"