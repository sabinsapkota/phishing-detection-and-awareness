
"""
Demo Data Generator for PhishGuard
Creates sample users and campaigns for demonstration
"""

from app import app, db, User, SimulationCampaign, SimulationResult
from werkzeug.security import generate_password_hash
import datetime

def create_demo_data():
    with app.app_context():
        print("Creating demo data...")

        # Create sample users
        departments = ['IT', 'HR', 'Finance', 'Marketing', 'Operations']
        users = []

        for i, dept in enumerate(departments):
            for j in range(3):  # 3 users per department
                username = f"user_{dept.lower()}_{j+1}"
                if not User.query.filter_by(username=username).first():
                    user = User(
                        username=username,
                        email=f"{username}@company.com",
                        password_hash=generate_password_hash('password123'),
                        role='user',
                        department=dept
                    )
                    db.session.add(user)
                    users.append(user)

        db.session.commit()
        print(f"✓ Created {len(users)} demo users")

        # Create sample campaigns
        campaigns_data = [
            {
                'name': 'Q4 Password Reset Test',
                'description': 'Testing user awareness of fake password reset emails',
                'template_type': 'password_reset',
                'target_group': 'all',
                'status': 'completed'
            },
            {
                'name': 'Finance Department - Tax Refund Scam',
                'description': 'Testing susceptibility to tax refund phishing',
                'template_type': 'tax_refund',
                'target_group': 'Finance',
                'status': 'active'
            },
            {
                'name': 'IT Security Awareness - Shipping',
                'description': 'Testing recognition of fake delivery notifications',
                'template_type': 'shipping_notification',
                'target_group': 'IT',
                'status': 'draft'
            }
        ]

        for camp_data in campaigns_data:
            if not SimulationCampaign.query.filter_by(name=camp_data['name']).first():
                campaign = SimulationCampaign(
                    name=camp_data['name'],
                    description=camp_data['description'],
                    template_type=camp_data['template_type'],
                    target_group=camp_data['target_group'],
                    start_date=datetime.datetime.now(),
                    end_date=datetime.datetime.now() + datetime.timedelta(days=30),
                    status=camp_data['status'],
                    created_by=1  # Admin user
                )
                db.session.add(campaign)

        db.session.commit()
        print(f"✓ Created {len(campaigns_data)} demo campaigns")

        # Create some simulation results for completed campaign
        completed_campaign = SimulationCampaign.query.filter_by(status='completed').first()
        if completed_campaign:
            all_users = User.query.filter_by(role='user').all()
            for user in all_users[:5]:  # Assign to first 5 users
                if not SimulationResult.query.filter_by(
                    campaign_id=completed_campaign.id, 
                    user_id=user.id
                ).first():
                    result = SimulationResult(
                        campaign_id=completed_campaign.id,
                        user_id=user.id,
                        email_sent=True,
                        email_opened=True,
                        link_clicked=True,  # Some clicked
                        reported_phishing=False,
                        training_completed=True
                    )
                    db.session.add(result)

            # Some reported correctly
            for user in all_users[5:8]:
                if not SimulationResult.query.filter_by(
                    campaign_id=completed_campaign.id, 
                    user_id=user.id
                ).first():
                    result = SimulationResult(
                        campaign_id=completed_campaign.id,
                        user_id=user.id,
                        email_sent=True,
                        email_opened=True,
                        link_clicked=False,
                        reported_phishing=True,
                        training_completed=False
                    )
                    db.session.add(result)

            db.session.commit()
            print("✓ Created demo simulation results")

        print("
Demo data creation complete!")
        print("
Demo Users:")
        print("- username: user_it_1, password: password123, dept: IT")
        print("- username: user_hr_1, password: password123, dept: HR")
        print("- username: user_finance_1, password: password123, dept: Finance")
        print("
Admin:")
        print("- username: admin, password: admin123")

if __name__ == '__main__':
    create_demo_data()
